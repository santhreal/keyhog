//! vyre_driver::VyreBackend implementation and core WgpuBackend methods.

use crate::{AdapterRecoveryTarget, DispatchArena, WgpuBackend};
use std::hash::BuildHasherDefault;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;
use vyre_driver::persistent::PersistentThreadMode;
use vyre_driver::speculate::SpeculationMode;
use vyre_foundation::ir::Program;

impl WgpuBackend {
    /// Adapter information selected for this backend instance.
    #[must_use]
    pub fn adapter_info(&self) -> &wgpu::AdapterInfo {
        &self.adapter_info
    }

    /// Device limits for this backend instance.
    #[must_use]
    pub fn device_limits(&self) -> &wgpu::Limits {
        &self.device_limits
    }

    /// Acquire the backend, probing adapters and returning a structured error
    /// when no compatible GPU is found.
    pub fn acquire() -> Result<Self, vyre_driver::BackendError> {
        let ((device, queue), adapter_info, enabled_features) = crate::runtime::init_device()
            .map_err(|error| {
                let instance = wgpu::Instance::default();
                let adapters: Vec<_> = instance.enumerate_adapters(wgpu::Backends::all());
                let mut probed = Vec::new();
                let mut missing = Vec::new();
                for adapter in adapters {
                    let info = adapter.get_info();
                    probed.push(format!(
                        "{} ({:?}, backend={:?})",
                        info.name, info.device_type, info.backend
                    ));
                    if matches!(
                        info.device_type,
                        wgpu::DeviceType::Cpu | wgpu::DeviceType::Other
                    ) {
                        continue;
                    }
                    if !adapter.features().contains(wgpu::Features::TIMESTAMP_QUERY) {
                        missing.push("TIMESTAMP_QUERY".to_string());
                    }
                    if !adapter
                        .features()
                        .contains(wgpu::Features::TIMESTAMP_QUERY_INSIDE_ENCODERS)
                    {
                        missing.push("TIMESTAMP_QUERY_INSIDE_ENCODERS".to_string());
                    }
                    let adapter_limits = adapter.limits();
                    if let Err(e) = pollster::block_on(adapter.request_device(
                        &wgpu::DeviceDescriptor {
                            label: Some("vyre probe"),
                            required_features: wgpu::Features::empty(),
                            required_limits: wgpu::Limits {
                                max_storage_buffers_per_shader_stage:
                                    adapter_limits.max_storage_buffers_per_shader_stage,
                                ..wgpu::Limits::default()
                            },
                            memory_hints: wgpu::MemoryHints::default(),
                        },
                        None,
                    )) {
                        missing.push(format!("device request failed on {}: {e}", info.name));
                    }
                }
                vyre_driver::BackendError::new(format!(
                    "no compatible GPU adapter found. Probed adapters: [{}].                  Missing features / limits: [{}]. Underlying error: {error}.                  Fix: install a compatible GPU driver and ensure a wgpu-supported backend                  (Vulkan, Metal, DX12) is available.",
                    probed.join(", "),
                    if missing.is_empty() {
                        "none".to_string()
                    } else {
                        missing.join(", ")
                    }
                ))
            })?;
        let recovery_target = AdapterRecoveryTarget::Identity(
            crate::runtime::device::AdapterIdentity::from_info(&adapter_info),
        );
        Self::from_device_queue(
            device,
            queue,
            adapter_info,
            enabled_features,
            recovery_target,
        )
    }

    /// Acquire a backend bound to a specific enumerable adapter index.
    pub fn acquire_adapter(index: usize) -> Result<Self, vyre_driver::BackendError> {
        let ((device, queue), adapter_info, enabled_features) =
            crate::runtime::device::init_device_for_adapter(index)
                .map_err(|error| vyre_driver::BackendError::new(error.to_string()))?;
        Self::from_device_queue(
            device,
            queue,
            adapter_info,
            enabled_features,
            AdapterRecoveryTarget::Index(index),
        )
    }

    fn from_device_queue(
        device: wgpu::Device,
        queue: wgpu::Queue,
        adapter_info: wgpu::AdapterInfo,
        enabled_features: crate::runtime::device::EnabledFeatures,
        recovery_target: AdapterRecoveryTarget,
    ) -> Result<Self, vyre_driver::BackendError> {
        let device_limits = device.limits();
        let adapter_name = Arc::<str>::from(adapter_info.name.as_str());
        let persistent_pool = crate::buffer::BufferPool::with_tiering(
            device.clone(),
            queue.clone(),
            &vyre_driver::DispatchConfig::default(),
            vec![
                crate::runtime::cache::CacheTier::new("hot", 1 << 24),
                crate::runtime::cache::CacheTier::new("cold", 1 << 30),
            ],
        )?;
        let (pipeline_cache_entries, pipeline_cache_bytes) =
            vyre_driver::pipeline::pipeline_cache_limits_from_env();
        Ok(Self {
            adapter_name,
            adapter_info,
            device_limits,
            device_queue: Arc::new(arc_swap::ArcSwap::new(Arc::new((device.clone(), queue.clone())))),
            dispatch_arena: Arc::new(arc_swap::ArcSwap::from_pointee(DispatchArena::new(
                device.clone(),
                queue.clone(),
                &vyre_driver::DispatchConfig::default(),
            ))),
            persistent_pool: Arc::new(arc_swap::ArcSwap::new(Arc::new(persistent_pool))),
            pipeline_cache: Arc::new(
                crate::runtime::cache::pipeline::LruPipelineCache::with_limits(
                    pipeline_cache_entries,
                    pipeline_cache_bytes,
                ),
            ),
            wgsl_dispatch_pipeline_cache: Arc::new(dashmap::DashMap::with_hasher(
                BuildHasherDefault::<rustc_hash::FxHasher>::default(),
            )),
            validation_cache: Arc::new(vyre_driver::validation::ValidationCache::default()),
            shape_history: Arc::new(std::sync::Mutex::new(
                vyre_driver::shape_prediction::ShapeHistory::new(),
            )),
            predicted_programs: Arc::new(dashmap::DashMap::with_hasher(BuildHasherDefault::<
                rustc_hash::FxHasher,
            >::default())),
            bind_group_layout_cache: Arc::new(dashmap::DashMap::with_hasher(BuildHasherDefault::<
                rustc_hash::FxHasher,
            >::default(
            ))),
            device_lost: Arc::new(AtomicBool::new(false)),
            enabled_features,
            recovery_target,
        })
    }

    pub(crate) fn current_device_queue(&self) -> Arc<(wgpu::Device, wgpu::Queue)> {
        self.device_queue.load_full()
    }

    /// Consumer-visible snapshot of the live wgpu device + queue.
    #[must_use]
    pub fn device_queue(&self) -> Arc<(wgpu::Device, wgpu::Queue)> {
        self.current_device_queue()
    }

    pub(crate) fn current_persistent_pool(&self) -> crate::buffer::BufferPool {
        self.persistent_pool.load_full().as_ref().clone()
    }

    pub(crate) fn dispatch_arena_snapshot(&self) -> Arc<DispatchArena> {
        self.dispatch_arena.load_full()
    }

    pub(crate) fn validate_with_cache(
        &self,
        program: &Program,
    ) -> Result<(), vyre_driver::BackendError> {
        self.validation_cache.get_or_validate_backend(program, self)
    }

    /// Test-only hook that marks the backend device as lost and invalidates
    /// caches tied to the current device generation.
    pub fn force_device_lost(&self) -> Result<(), vyre_driver::BackendError> {
        self.device_lost.store(true, Ordering::Release);
        self.pipeline_cache.clear();
        self.wgsl_dispatch_pipeline_cache.clear();
        self.bind_group_layout_cache.clear();
        self.validation_cache.clear()?;
        let device_queue = self.device_queue.load_full();
        self.dispatch_arena.store(Arc::new(DispatchArena::new(
            device_queue.0.clone(),
            device_queue.1.clone(),
            &vyre_driver::DispatchConfig::default(),
        )));
        Ok(())
    }

    /// Invalidate compiled pipeline artifacts selected by a rule-impact mask.
    pub fn invalidate_impacted_pipeline_cache(
        &self,
        intervention_mask: &[u32],
        rule_adj: &[u32],
        state: &[u32],
        join_rules: &[u32],
        n: u32,
        max_iterations: u32,
        pipeline_lineage_cell: &[u32],
        pipeline_keys: &[[u8; 32]],
    ) {
        let final_impact_mask = vyre_driver::cache_invalidation::impacted_entries(
            intervention_mask,
            rule_adj,
            state,
            join_rules,
            n,
            max_iterations,
            pipeline_lineage_cell,
        );
        self.pipeline_cache
            .invalidate_impacted(&final_impact_mask, pipeline_keys);
    }

    /// Convenience wrapper around [`Self::invalidate_impacted_pipeline_cache`]
    pub fn invalidate_pipeline_cache_for_changed_op(
        &self,
        changed_op_handle: u32,
        pipeline_lineage_cell: &[u32],
        pipeline_keys: &[[u8; 32]],
    ) {
        let n = 1u32;
        let rule_adj = vec![1u32];
        let intervention_mask = vec![1u32];
        let state = vec![1u32];
        let join_rules = vec![1u32];
        let max_iterations = 1u32;
        let normalized_lineage_cell: Vec<u32> = pipeline_lineage_cell
            .iter()
            .map(|&op| if op == changed_op_handle { 0 } else { u32::MAX })
            .collect();
        self.invalidate_impacted_pipeline_cache(
            &intervention_mask,
            &rule_adj,
            &state,
            &join_rules,
            n,
            max_iterations,
            &normalized_lineage_cell,
            pipeline_keys,
        );
    }

    /// Invalidate disk-cached pipeline artifacts selected by a rule-impact mask.
    pub fn invalidate_impacted_disk_cache(
        &self,
        intervention_mask: &[u32],
        rule_adj: &[u32],
        state: &[u32],
        join_rules: &[u32],
        n: u32,
        max_iterations: u32,
        pipeline_lineage_cell: &[u32],
        cache_keys: &[String],
    ) -> Result<(), vyre_driver::BackendError> {
        crate::pipeline::disk_cache::invalidate_impacted(
            intervention_mask,
            rule_adj,
            state,
            join_rules,
            n,
            max_iterations,
            pipeline_lineage_cell,
            cache_keys,
        )
        .map_err(|e| vyre_driver::BackendError::new(e.to_string()))
    }

    /// Create the backend if a GPU adapter is available.
    #[must_use]
    #[inline]
    pub fn new() -> Result<Self, vyre_driver::BackendError> {
        Self::acquire().map_err(|e| vyre_driver::BackendError::new(e.to_string()))
    }

    /// Process-wide shared backend handle.
    pub fn shared() -> Result<Arc<Self>, vyre_driver::BackendError> {
        static SHARED: std::sync::OnceLock<Result<Arc<WgpuBackend>, String>> =
            std::sync::OnceLock::new();
        match SHARED.get_or_init(|| Self::new().map(Arc::new).map_err(|e| e.to_string())) {
            Ok(arc) => Ok(arc.clone()),
            Err(msg) => Err(vyre_driver::BackendError::new(msg.clone())),
        }
    }

    /// Dispatch borrowed inputs and visit each mapped output byte slice.
    pub fn dispatch_borrowed_for_each_mapped_output<F>(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &vyre_driver::DispatchConfig,
        visitor: F,
    ) -> Result<(), vyre_driver::BackendError>
    where
        F: FnMut(usize, &[u8]) -> Result<(), vyre_driver::BackendError>,
    {
        let _span = tracing::trace_span!(
            "vyre.dispatch_mapped_outputs",
            backend = "wgpu",
            inputs = inputs.len(),
            label = tracing::field::Empty,
        );
        let _enter = _span.enter();
        if let Some(label) = config.label.as_deref() {
            _span.record("label", label);
        }
        let start = Instant::now();
        self.dispatch_borrowed_async(program, inputs, config)?
            .await_mapped_outputs(visitor)?;
        tracing::trace!(
            target: "vyre.dispatch",
            elapsed_us = start.elapsed().as_micros() as u64,
            inputs = inputs.len(),
            "mapped-output dispatch completed"
        );
        Ok(())
    }

    /// Dispatch borrowed inputs and visit each mapped output as a typed POD slice.
    pub fn dispatch_borrowed_for_each_pod_output<T, F>(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &vyre_driver::DispatchConfig,
        mut visitor: F,
    ) -> Result<(), vyre_driver::BackendError>
    where
        T: bytemuck::Pod,
        F: FnMut(usize, &[T]) -> Result<(), vyre_driver::BackendError>,
    {
        self.dispatch_borrowed_for_each_mapped_output(program, inputs, config, |index, bytes| {
            let typed = bytemuck::try_cast_slice::<u8, T>(bytes).map_err(|error| {
                vyre_driver::BackendError::new(format!(
                    "mapped output #{index} cannot be viewed as {}: {error}. Fix: set output_byte_range to a length and offset aligned for the requested POD type.",
                    std::any::type_name::<T>()
                ))
            })?;
            visitor(index, typed)
        })
    }

    /// Enforce capability requirements declared in `config`.
    pub(crate) fn enforce_config_caps(
        &self,
        config: &vyre_driver::DispatchConfig,
    ) -> Result<(), vyre_driver::BackendError> {
        if matches!(config.speculation, Some(SpeculationMode::Force))
            && !<Self as vyre_driver::VyreBackend>::supports_speculation(self)
        {
            return Err(vyre_driver::BackendError::UnsupportedFeature {
                name: "speculative dispatch".to_string(),
                backend: <Self as vyre_driver::VyreBackend>::id(self).to_string(),
            });
        }
        if matches!(config.persistent_thread, Some(PersistentThreadMode::Force))
            && !<Self as vyre_driver::VyreBackend>::supports_persistent_thread_dispatch(self)
        {
            return Err(vyre_driver::BackendError::UnsupportedFeature {
                name: "persistent-thread dispatch".to_string(),
                backend: <Self as vyre_driver::VyreBackend>::id(self).to_string(),
            });
        }
        Ok(())
    }

    /// Dispatch a real prefilter/confirm scan through the adaptive speculative path.
    pub fn dispatch_speculative_prefilter_confirm<F>(
        &self,
        speculator: &vyre_driver::speculate::AdaptiveSpeculator,
        plan: vyre_driver::speculate::SpeculativeDispatchPlan<'_>,
        inputs: &[&[u8]],
        config: &vyre_driver::DispatchConfig,
        confirm_serial: F,
    ) -> Result<vyre_driver::speculate::SpeculativeDispatchOutcome, vyre_driver::BackendError>
    where
        F: FnMut(
            vyre_driver::OutputBuffers,
        ) -> Result<vyre_driver::OutputBuffers, vyre_driver::BackendError>,
    {
        vyre_driver::speculate::dispatch_prefilter_confirm(
            self,
            speculator,
            plan,
            inputs,
            config,
            confirm_serial,
        )
    }

    fn record_borrowed_batch_job(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &vyre_driver::DispatchConfig,
        started: Instant,
    ) -> Result<crate::engine::record_and_readback::RecordedDispatch, vyre_driver::BackendError>
    {
        self.enforce_config_caps(config)?;
        self.validate_with_cache(program)?;
        let pipeline = crate::pipeline::WgpuPipeline::compile_with_device_queue(
            program,
            config,
            self.adapter_info.clone(),
            self.enabled_features,
            self.current_device_queue(),
            self.dispatch_arena_snapshot(),
            self.current_persistent_pool(),
            self.pipeline_cache.clone(),
            self.bind_group_layout_cache.clone(),
        )?;
        if let Some(deadline) = config.timeout {
            let elapsed = started.elapsed();
            if elapsed > deadline {
                return Err(vyre_driver::BackendError::new(format!(
                    "batch dispatch cancelled before GPU submission: took {elapsed:?}, budget {deadline:?}.                      Fix: raise DispatchConfig.timeout or split the program into smaller chunks."
                )));
            }
        }
        let workgroup_count = pipeline.workgroups_for_dispatch(config)?;
        let dispatch_arena = self.dispatch_arena_snapshot();
        crate::engine::record_and_readback::record_dispatch_unsubmitted(
            crate::engine::record_and_readback::RecordAndReadback::for_dispatch(
                &pipeline,
                &dispatch_arena,
                inputs,
                workgroup_count,
                config,
                crate::async_dispatch::timestamp_profile_requested(config),
                crate::engine::record_and_readback::DispatchLabels {
                    readback: "vyre batch dispatch readback",
                    bind_group: "vyre batch dispatch bind group",
                    encoder: "vyre batch dispatch",
                    compute: "vyre batch dispatch compute",
                },
            ),
        )
    }

    /// Dispatch a batch of borrowed `(Program, inputs, config)` triples.
    pub fn dispatch_borrowed_batch(
        &self,
        jobs: &[(&Program, &[&[u8]], &vyre_driver::DispatchConfig)],
    ) -> Result<
        Vec<Result<vyre_driver::OutputBuffers, vyre_driver::BackendError>>,
        vyre_driver::BackendError,
    > {
        let _span = tracing::trace_span!(
            "vyre.dispatch_borrowed_batch",
            backend = "wgpu",
            jobs = jobs.len(),
        );
        let _enter = _span.enter();

        let mut results: Vec<
            Option<Result<vyre_driver::OutputBuffers, vyre_driver::BackendError>>,
        > = std::iter::repeat_with(|| None).take(jobs.len()).collect();
        let mut recorded = Vec::with_capacity(jobs.len());
        let mut meta = Vec::with_capacity(jobs.len());
        for (index, (program, inputs, config)) in jobs.iter().enumerate() {
            let started = Instant::now();
            if program.is_explicit_noop() {
                results[index] = Some(Ok(Vec::new()));
                continue;
            }
            let command = self.record_borrowed_batch_job(program, inputs, config, started)?;
            recorded.push(command);
            meta.push((index, started, config.timeout));
        }

        let pending = crate::engine::record_and_readback::submit_recorded_batch(recorded)?;
        for ((index, started, timeout), result) in meta
            .into_iter()
            .zip(crate::engine::record_and_readback::WgpuPendingReadback::await_many_owned(pending))
        {
            results[index] = Some(result.and_then(|outputs| {
                if let Some(deadline) = timeout {
                    let elapsed = started.elapsed();
                    if elapsed > deadline {
                        return Err(vyre_driver::BackendError::new(format!(
                            "batch dispatch exceeded configured timeout: took {elapsed:?}, budget {deadline:?}.                              Fix: raise DispatchConfig.timeout or split the program into smaller chunks."
                        )));
                    }
                }
                Ok(outputs)
            }));
        }
        Ok(results
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|| {
                    Err(vyre_driver::BackendError::new(
                        "internal batch dispatch result slot was not filled. Fix: keep batch recording metadata synchronized.",
                    ))
                })
            })
            .collect())
    }

    /// Dispatch a borrowed batch and write each job's outputs into caller-owned per-job output buffers.
    pub fn dispatch_borrowed_batch_into(
        &self,
        jobs: &[(&Program, &[&[u8]], &vyre_driver::DispatchConfig)],
        outputs: &mut [vyre_driver::OutputBuffers],
    ) -> Result<Vec<Result<(), vyre_driver::BackendError>>, vyre_driver::BackendError> {
        if outputs.len() != jobs.len() {
            return Err(vyre_driver::BackendError::new(format!(
                "dispatch_borrowed_batch_into received {} output slots for {} jobs. Fix: pass exactly one OutputBuffers slot per job.",
                outputs.len(),
                jobs.len()
            )));
        }

        let _span = tracing::trace_span!(
            "vyre.dispatch_borrowed_batch_into",
            backend = "wgpu",
            jobs = jobs.len(),
        );
        let _enter = _span.enter();

        let mut results: Vec<Option<Result<(), vyre_driver::BackendError>>> =
            std::iter::repeat_with(|| None).take(jobs.len()).collect();
        let mut recorded = Vec::with_capacity(jobs.len());
        let mut meta = Vec::with_capacity(jobs.len());
        for (index, (program, inputs, config)) in jobs.iter().enumerate() {
            let started = Instant::now();
            if program.is_explicit_noop() {
                outputs[index].clear();
                results[index] = Some(Ok(()));
                continue;
            }
            let command = self.record_borrowed_batch_job(program, inputs, config, started)?;
            recorded.push(command);
            meta.push((index, started, config.timeout));
        }

        let pending = crate::engine::record_and_readback::submit_recorded_batch(recorded)?;
        let deadline =
            crate::engine::record_and_readback::WgpuPendingReadback::wait_for_many(&pending);
        for ((index, started, timeout), readback) in meta.into_iter().zip(pending) {
            results[index] = Some(
                readback
                    .collect_after_submission_wait(&mut outputs[index], deadline)
                    .and_then(|()| {
                        if let Some(deadline) = timeout {
                            let elapsed = started.elapsed();
                            if elapsed > deadline {
                                return Err(vyre_driver::BackendError::new(format!(
                                    "batch dispatch exceeded configured timeout: took {elapsed:?}, budget {deadline:?}.                                      Fix: raise DispatchConfig.timeout or split the program into smaller chunks."
                                )));
                            }
                        }
                        Ok(())
                    }),
            );
        }
        Ok(results
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|| {
                    Err(vyre_driver::BackendError::new(
                        "internal batch-into dispatch result slot was not filled. Fix: keep batch recording metadata synchronized.",
                    ))
                })
            })
            .collect())
    }

    /// Dispatch an owned batch of `(Program, inputs, config)` triples.
    pub fn dispatch_batch(
        &self,
        jobs: &[(
            vyre_foundation::ir::Program,
            Vec<Vec<u8>>,
            vyre_driver::DispatchConfig,
        )],
    ) -> Result<
        Vec<Result<vyre_driver::OutputBuffers, vyre_driver::BackendError>>,
        vyre_driver::BackendError,
    > {
        let borrowed_inputs: Vec<smallvec::SmallVec<[&[u8]; 8]>> = jobs
            .iter()
            .map(|(_, inputs, _)| inputs.iter().map(Vec::as_slice).collect())
            .collect();
        let borrowed_jobs: Vec<(&Program, &[&[u8]], &vyre_driver::DispatchConfig)> = jobs
            .iter()
            .zip(borrowed_inputs.iter())
            .map(|((program, _, config), inputs)| (program, inputs.as_slice(), config))
            .collect();
        self.dispatch_borrowed_batch(&borrowed_jobs)
    }

    /// Compile a program into a host-ingress wgpu stream.
    #[allow(deprecated)]
    pub fn compile_streaming(
        &self,
        program: &vyre_foundation::ir::Program,
        config: vyre_driver::DispatchConfig,
    ) -> Result<crate::engine::streaming::HostIngressStream, vyre_driver::BackendError> {
        self.enforce_config_caps(&config)?;
        let pipeline = crate::pipeline::WgpuPipeline::compile_with_device_queue(
            program,
            &config,
            self.adapter_info.clone(),
            self.enabled_features,
            self.current_device_queue(),
            self.dispatch_arena_snapshot(),
            self.current_persistent_pool(),
            self.pipeline_cache.clone(),
            self.bind_group_layout_cache.clone(),
        )?;
        Ok(crate::engine::streaming::HostIngressStream::new(
            (*pipeline).clone(),
            config,
        ))
    }

    /// Compile a program into a persistent pipeline.
    pub fn compile_persistent(
        &self,
        program: &vyre_foundation::ir::Program,
        config: &vyre_driver::DispatchConfig,
    ) -> Result<Arc<crate::pipeline::WgpuPipeline>, vyre_driver::BackendError> {
        self.enforce_config_caps(config)?;
        crate::pipeline::WgpuPipeline::compile_with_device_queue(
            program,
            config,
            self.adapter_info.clone(),
            self.enabled_features,
            self.current_device_queue(),
            self.dispatch_arena_snapshot(),
            self.current_persistent_pool(),
            self.pipeline_cache.clone(),
            self.bind_group_layout_cache.clone(),
        )
    }
}

/// Converts caller-owned input buffers into a [`smallvec::SmallVec`] of borrowed slices.
///
/// The wgpu backend's `dispatch_async` routes through this helper so staging reads from the
/// caller's [`Vec`] allocations without cloning payload bytes—only slice references are
/// collected into the vector. With more than eight inputs the [`SmallVec`] spills to heap
/// storage while elements still alias the original buffers.
#[allow(clippy::needless_lifetimes)]
pub(crate) fn borrowed_slices_from_owned_inputs<'a>(
    inputs: &'a [Vec<u8>],
) -> smallvec::SmallVec<[&'a [u8]; 8]> {
    inputs.iter().map(Vec::as_slice).collect()
}

impl vyre_driver::VyreBackend for WgpuBackend {
    fn id(&self) -> &'static str {
        "wgpu"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn supported_ops(&self) -> &std::collections::HashSet<vyre_foundation::ir::OpId> {
        vyre_driver::backend::validation::default_supported_ops_with_trap()
    }

    fn dispatch(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &vyre_driver::DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
        let _span = tracing::trace_span!(
            "vyre.dispatch",
            backend = "wgpu",
            inputs = inputs.len(),
            label = tracing::field::Empty,
        );
        let _enter = _span.enter();
        if let Some(label) = config.label.as_deref() {
            _span.record("label", label);
        }
        let borrowed: smallvec::SmallVec<[&[u8]; 8]> = inputs.iter().map(Vec::as_slice).collect();
        let start = Instant::now();
        let result = self
            .dispatch_borrowed_async(program, &borrowed, config)?
            .await_owned();
        tracing::trace!(
            target: "vyre.dispatch",
            elapsed_us = start.elapsed().as_micros() as u64,
            inputs = inputs.len(),
            "dispatch completed (borrowed-path; clone-free)"
        );
        result
    }

    fn dispatch_borrowed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &vyre_driver::DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
        let _span = tracing::trace_span!(
            "vyre.dispatch",
            backend = "wgpu",
            inputs = inputs.len(),
            label = tracing::field::Empty,
        );
        let _enter = _span.enter();
        if let Some(label) = config.label.as_deref() {
            _span.record("label", label);
        }
        let start = Instant::now();
        let result = self
            .dispatch_borrowed_async(program, inputs, config)?
            .await_owned();
        tracing::trace!(
            target: "vyre.dispatch",
            elapsed_us = start.elapsed().as_micros() as u64,
            inputs = inputs.len(),
            "dispatch completed"
        );
        result
    }

    fn dispatch_borrowed_into(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &vyre_driver::DispatchConfig,
        outputs: &mut vyre_driver::OutputBuffers,
    ) -> Result<(), vyre_driver::BackendError> {
        let _span = tracing::trace_span!(
            "vyre.dispatch_into",
            backend = "wgpu",
            inputs = inputs.len(),
            label = tracing::field::Empty,
        );
        let _enter = _span.enter();
        if let Some(label) = config.label.as_deref() {
            _span.record("label", label);
        }
        let start = Instant::now();
        self.dispatch_borrowed_async(program, inputs, config)?
            .await_into(outputs)?;
        tracing::trace!(
            target: "vyre.dispatch",
            elapsed_us = start.elapsed().as_micros() as u64,
            inputs = inputs.len(),
            "dispatch completed into caller-owned outputs"
        );
        Ok(())
    }

    fn dispatch_async(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &vyre_driver::DispatchConfig,
    ) -> Result<Box<dyn vyre_driver::backend::PendingDispatch>, vyre_driver::BackendError> {
        let _span = tracing::trace_span!(
            "vyre.dispatch_async",
            backend = "wgpu",
            inputs = inputs.len(),
            label = tracing::field::Empty,
        );
        let _enter = _span.enter();
        if let Some(label) = config.label.as_deref() {
            _span.record("label", label);
        }

        let borrowed = borrowed_slices_from_owned_inputs(inputs);
        Ok(Box::new(WgpuBackend::dispatch_borrowed_async(
            self, program, &borrowed, config,
        )?))
    }

    fn dispatch_borrowed_async(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &vyre_driver::DispatchConfig,
    ) -> Result<Box<dyn vyre_driver::backend::PendingDispatch>, vyre_driver::BackendError> {
        Ok(Box::new(WgpuBackend::dispatch_borrowed_async(
            self, program, inputs, config,
        )?))
    }

    fn compile_native(
        &self,
        program: &Program,
        config: &vyre_driver::DispatchConfig,
    ) -> Result<Option<std::sync::Arc<dyn vyre_driver::CompiledPipeline>>, vyre_driver::BackendError>
    {
        self.enforce_config_caps(config)?;
        self.validate_with_cache(program)?;
        let cached = crate::pipeline::WgpuPipeline::compile_with_device_queue(
            program,
            config,
            self.adapter_info.clone(),
            self.enabled_features,
            self.current_device_queue(),
            self.dispatch_arena_snapshot(),
            self.current_persistent_pool(),
            self.pipeline_cache.clone(),
            self.bind_group_layout_cache.clone(),
        )?;
        Ok(Some(cached))
    }

    fn pipeline_cache_snapshot(&self) -> Option<vyre_driver::pipeline::PipelineCacheSnapshot> {
        Some(vyre_driver::pipeline::PipelineCacheSnapshot {
            hits: self.pipeline_cache.hits(),
            misses: self.pipeline_cache.misses(),
        })
    }

    fn supports_subgroup_ops(&self) -> bool {
        crate::capabilities::supports_subgroup_ops(&self.enabled_features)
    }

    fn supports_f16(&self) -> bool {
        false
    }

    fn supports_bf16(&self) -> bool {
        false
    }

    fn supports_tensor_cores(&self) -> bool {
        false
    }

    fn supports_async_compute(&self) -> bool {
        false
    }

    fn supports_indirect_dispatch(&self) -> bool {
        crate::capabilities::supports_indirect_dispatch(&self.adapter_info, &self.enabled_features)
    }

    fn supports_speculation(&self) -> bool {
        false
    }

    fn supports_persistent_thread_dispatch(&self) -> bool {
        false
    }

    fn is_distributed(&self) -> bool {
        false
    }

    fn max_workgroup_size(&self) -> [u32; 3] {
        self.enabled_features.max_workgroup_size
    }

    fn max_compute_workgroups_per_dimension(&self) -> u32 {
        self.device_limits.max_compute_workgroups_per_dimension
    }

    fn max_compute_invocations_per_workgroup(&self) -> u32 {
        self.device_limits.max_compute_invocations_per_workgroup
    }

    fn subgroup_size(&self) -> Option<u32> {
        crate::capabilities::supports_subgroup_ops(&self.enabled_features)
            .then_some(self.enabled_features.min_subgroup_size)
    }

    fn max_storage_buffer_bytes(&self) -> u64 {
        self.enabled_features.max_storage_buffer_binding_size
    }

    fn device_profile(&self) -> vyre_driver::DeviceProfile {
        WgpuBackend::device_profile(self)
    }

    fn flush(&self) -> Result<(), vyre_driver::BackendError> {
        let device_queue = self.current_device_queue();
        let submission = device_queue.1.submit(std::iter::empty());
        match device_queue.0.poll(wgpu::Maintain::wait_for(submission)) {
            wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {
                crate::pipeline::disk_cache::flush_disk_pipeline_cache()
            }
        }
    }

    fn device_lost(&self) -> bool {
        self.device_lost.load(Ordering::Acquire)
    }

    fn try_recover(&self) -> Result<(), vyre_driver::BackendError> {
        let ((device, queue), adapter_info, enabled) = match &self.recovery_target {
            AdapterRecoveryTarget::Index(index) => {
                crate::runtime::device::init_device_for_adapter(*index)
            }
            AdapterRecoveryTarget::Identity(identity) => {
                crate::runtime::device::init_device_for_adapter_identity(identity)
            }
        }
        .map_err(|error| vyre_driver::BackendError::new(error.to_string()))?;
        let device_limits = device.limits();
        let recovered_identity = crate::runtime::device::AdapterIdentity::from_info(&adapter_info);
        let original_identity =
            crate::runtime::device::AdapterIdentity::from_info(&self.adapter_info);
        if recovered_identity != original_identity {
            return Err(vyre_driver::BackendError::new(format!(
                "wgpu recovery selected a different adapter than the backend was constructed with. Original: {:?}; recovered: {:?}. Fix: construct a new backend for the new adapter instead of reusing device-local caches across adapter identities.",
                self.adapter_info, adapter_info
            )));
        }
        if device_limits != self.device_limits || enabled != self.enabled_features {
            return Err(vyre_driver::BackendError::new(
                "wgpu recovery selected the original adapter but feature or limit negotiation changed. Fix: construct a new backend so dispatch planning and pipeline caches are rebuilt against the new device contract.",
            ));
        }
        let persistent_pool = crate::buffer::BufferPool::with_tiering(
            device.clone(),
            queue.clone(),
            &vyre_driver::DispatchConfig::default(),
            vec![
                crate::runtime::cache::CacheTier::new("hot", 1 << 24),
                crate::runtime::cache::CacheTier::new("cold", 1 << 30),
            ],
        )?;
        self.device_queue.store(Arc::new((device.clone(), queue.clone())));
        self.persistent_pool.store(Arc::new(persistent_pool));
        self.pipeline_cache.clear();
        self.wgsl_dispatch_pipeline_cache.clear();
        self.bind_group_layout_cache.clear();
        self.validation_cache.clear()?;
        self.dispatch_arena.store(Arc::new(DispatchArena::new(
            device.clone(),
            queue.clone(),
            &vyre_driver::DispatchConfig::default(),
        )));
        self.device_lost.store(false, Ordering::Release);

        Ok(())
    }
}

#[cfg(test)]
mod borrowed_slice_conversion_tests {
    use super::borrowed_slices_from_owned_inputs;

    #[test]
    fn dispatch_async_input_conversion_is_zero_copy_slice_refs() {
        let inputs = vec![vec![1u8, 2, 3], vec![4u8, 5]];
        let borrowed = borrowed_slices_from_owned_inputs(&inputs);
        assert_eq!(borrowed.len(), 2);
        assert_eq!(borrowed[0].as_ptr(), inputs[0].as_ptr());
        assert_eq!(borrowed[1].as_ptr(), inputs[1].as_ptr());
    }

    #[test]
    fn nine_inputs_spill_smallvec_but_slices_alias_vecs() {
        let inputs: Vec<Vec<u8>> = (0..9).map(|i| vec![i as u8]).collect();
        let borrowed = borrowed_slices_from_owned_inputs(&inputs);
        assert_eq!(borrowed.len(), 9);
        for i in 0..9 {
            assert_eq!(
                borrowed[i].as_ptr(),
                inputs[i].as_ptr(),
                "slice {i} must reference the corresponding Vec buffer"
            );
        }
    }
}
