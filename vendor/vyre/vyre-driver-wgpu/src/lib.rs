#![allow(
    unstable_name_collisions,
    clippy::field_reassign_with_default,
    clippy::double_must_use,
    clippy::type_complexity,
    clippy::missing_errors_doc,
    clippy::too_many_arguments,
    clippy::manual_clamp,
    clippy::module_inception,
    clippy::empty_line_after_doc_comments,
    clippy::let_and_return,
    clippy::missing_safety_doc
)]
#![deny(unsafe_code)]
#![deny(missing_docs)]

//! # vyre-wgpu — wgpu backend for the vyre GPU compute specification
//!
//! Implements [`vyre::VyreBackend`] on `wgpu::Device` + `wgpu::Queue`. Owns
//! the GPU runtime: device acquisition, buffer pool, pipeline cache, shader
//! compilation, and dispatch. Consumers call `WgpuBackend::dispatch(&program,
//! &inputs, &config)`; lowering to backend IR and emitting WGSL happen inside
//! this crate.
//!
//! This crate has exactly one responsibility: dispatch a vyre `Program` on
//! wgpu. Every other concern — IR construction, algebraic law verification,
//! certificate generation — lives in a sibling crate.

mod async_dispatch;
mod capabilities;
pub mod pipeline;
mod pipeline_compound;
mod pipeline_disk_cache;
mod pipeline_persistent;

/// Persistent GPU buffer handles and allocation pools.
pub mod buffer;

/// Backend-owned lowering from vyre Program to Naga IR plus shader emission.
pub mod lowering;

/// Persistent megakernel mode (C-B9).
///
/// Single long-running shader pops work items from a GPU-side
/// ring buffer. Opt-in; amortizes PCIe dispatch overhead for
/// streaming workloads.
pub mod megakernel;

/// SPIR-V emitter (C-B7).
///
/// Reuses every `LoweringTable::naga_wgsl` builder and emits
/// SPIR-V via `naga::back::spv::write_vec` instead of
/// WGSL text. Target = Vulkan backend through wgpu.
pub mod spirv_backend;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;
use vyre_driver::VyreBackend;
use vyre_foundation::ir::{DataType, Program};
use vyre_foundation::validate::BackendValidationCapabilities;

/// wgpu-backed host engines and runtime glue.
pub mod engine;
/// WGSL-specific extension API for the wgpu backend.
pub mod ext;

/// wgpu runtime: devices, queues, buffers, shaders, and cache management.
pub mod runtime;

/// A real wgpu backend for vyre.
///
/// This backend dispatches vyre IR programs on a real GPU adapter.
/// Construction returns a structured [`vyre::BackendError`] when adapter
/// probing, device creation, or required feature negotiation fails.
#[derive(Clone, Debug)]
pub struct WgpuBackend {
    adapter_info: wgpu::AdapterInfo,
    device_limits: wgpu::Limits,
    /// Shared device + queue handle (V7-PERF-011). Backed by
    /// `Arc<ArcSwap<...>>` — dispatches get the current pair via a
    /// lock-free atomic `load_full()`, and `try_recover` atomically
    /// swaps in a fresh `wgpu::Device` after a driver fault via
    /// `store()`. No lock contention and no in-flight-dispatch
    /// serialization: recovery completes as fast as the atomic swap
    /// regardless of outstanding dispatches (those observe the
    /// previous pair until they complete; the new pair is used by
    /// every call after `store`).
    pub(crate) device_queue: Arc<arc_swap::ArcSwap<(wgpu::Device, wgpu::Queue)>>,
    pub(crate) dispatch_arena: DispatchArena,
    /// Shared persistent GPU-handle pool (H1). Every pipeline
    /// produced by this backend gets a clone of this pool so legacy
    /// dispatch paths recycle `wgpu::Buffer` allocations across
    /// calls instead of churning the GPU allocator.
    pub(crate) persistent_pool: Arc<arc_swap::ArcSwap<crate::buffer::BufferPool>>,
    /// Device-local pipeline cache. Bounded LRU eviction is owned by
    /// [`runtime::cache::pipeline::LruPipelineCache`] so the cache
    /// cannot grow without bound (prior `DashMap` field leaked).
    pub(crate) pipeline_cache: Arc<runtime::cache::pipeline::LruPipelineCache>,
    /// Backend-specific validation cache preventing redundant capability checks.
    pub(crate) validation_cache: Arc<dashmap::DashSet<blake3::Hash>>,
    /// Test hook / lifecycle probe for simulated device loss.
    pub(crate) device_lost: Arc<AtomicBool>,
    pub(crate) enabled_features: crate::runtime::device::EnabledFeatures,
}

/// Backend-owned dispatch buffer arena.
///
/// Buffers are pooled by device, usage flags, and aligned size class so hot
/// repeated dispatches reuse GPU allocations while each backend instance keeps
/// independent ownership of its device and queue.
#[derive(Clone, Default)]
pub struct DispatchArena {
    pool: runtime::cache::BufferPool,
}

impl std::fmt::Debug for DispatchArena {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DispatchArena { pool: size-classed }")
    }
}

impl DispatchArena {
    /// Create an empty dispatch arena.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            pool: runtime::cache::BufferPool::new(),
        }
    }

    pub(crate) fn pool(&self) -> &runtime::cache::BufferPool {
        &self.pool
    }
}

impl BackendValidationCapabilities for WgpuBackend {
    fn backend_name(&self) -> &'static str {
        "wgpu"
    }

    fn supports_cast_target(&self, target: &DataType) -> bool {
        matches!(
            target,
            DataType::Bool
                | DataType::U8
                | DataType::U16
                | DataType::U32
                | DataType::U64
                | DataType::I8
                | DataType::I16
                | DataType::I32
                | DataType::F32
                | DataType::Vec2U32
                | DataType::Vec4U32
        )
    }

    fn supports_subgroup_ops(&self) -> bool {
        crate::capabilities::supports_subgroup_ops(&self.enabled_features)
    }

    fn supports_indirect_dispatch(&self) -> bool {
        crate::capabilities::supports_indirect_dispatch(&self.adapter_info, &self.enabled_features)
    }

    fn supports_specialization_constants(&self) -> bool {
        crate::capabilities::validation_capabilities(&self.adapter_info, &self.enabled_features)
            .supports_specialization_constants
    }
}

/// Runtime observability snapshot for a [`WgpuBackend`].
///
/// Feed into metrics pipelines (prometheus, OpenTelemetry, Datadog)
/// for dashboards and alerting. Reads are lock-free; safe to call
/// from a hot scrape loop.
#[derive(Clone, Debug)]
pub struct WgpuBackendStats {
    /// Adapter name the backend is bound to (e.g. `"NVIDIA GeForce RTX 5090"`).
    pub adapter_name: String,
    /// Live entries in the pipeline cache.
    pub pipeline_cache_entries: usize,
    /// Soft cap before eviction triggers.
    pub pipeline_cache_capacity: usize,
    /// Persistent buffer pool counters (allocations, hits, releases, evictions).
    pub persistent_pool: crate::buffer::BufferPoolStats,
}

// `Default` is intentionally not implemented on `WgpuBackend`.
//
// Backend construction can fail (adapter probing, device creation, or feature
// negotiation) and
// `Default::default()` would have to panic on failure — SAFE-01 in the
// 2026-04-18 safety audit flagged that as a HIGH-severity panic vector
// because `Default` gets called by frameworks, deserializers, and
// generic glue that cannot recover from a panic. Callers must go
// through [`WgpuBackend::acquire`], which returns a structured
// [`vyre::BackendError`] on failure and participates in capability
// negotiation (Law C).
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

    /// Optimizer-facing capability snapshot for this live backend.
    ///
    /// Unlike adapter-only probes, this reflects the features that were
    /// actually enabled on the device after backend construction.
    #[must_use]
    pub fn adapter_caps(&self) -> vyre_foundation::optimizer::AdapterCaps {
        crate::runtime::adapter_caps_probe::from_backend(
            &self.adapter_info,
            &self.device_limits,
            &self.enabled_features,
        )
    }

    /// Observability snapshot — pipeline cache size, buffer-pool
    /// stats, and adapter identity. SRE-friendly: consumers feed the
    /// returned numbers into prometheus / OpenTelemetry / Datadog
    /// pipelines for dashboards and alerting.
    ///
    /// Reads use atomic cache counters and the lock-free persistent-pool
    /// pointer, so the call is safe for metrics-scrape loops.
    #[must_use]
    pub fn stats(&self) -> WgpuBackendStats {
        let persistent_pool = self.current_persistent_pool().stats();
        WgpuBackendStats {
            adapter_name: self.adapter_info.name.clone(),
            pipeline_cache_entries: self.pipeline_cache.len(),
            pipeline_cache_capacity: crate::pipeline::MAX_PIPELINE_CACHE_ENTRIES,
            persistent_pool,
        }
    }

    /// Acquire the backend, probing adapters and returning a structured error
    /// when no compatible GPU is found.
    ///
    /// # Errors
    ///
    /// Returns a [`vyre::BackendError`] listing the probed adapter types and
    /// any missing features when initialization fails.
    pub fn acquire() -> Result<Self, vyre::BackendError> {
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
                vyre::BackendError::new(format!(
                    "no compatible GPU adapter found. Probed adapters: [{}]. \
                 Missing features / limits: [{}]. Underlying error: {error}. \
                 Fix: install a compatible GPU driver and ensure a wgpu-supported backend \
                 (Vulkan, Metal, DX12) is available.",
                    probed.join(", "),
                    if missing.is_empty() {
                        "none".to_string()
                    } else {
                        missing.join(", ")
                    }
                ))
            })?;
        let device_limits = device.limits();
        let persistent_pool = crate::buffer::BufferPool::with_tiering(
            device.clone(),
            queue.clone(),
            &vyre::DispatchConfig::default(),
            vec![
                crate::runtime::cache::CacheTier::new("hot", 1 << 24),
                crate::runtime::cache::CacheTier::new("cold", 1 << 30),
            ],
        );
        Ok(Self {
            adapter_info,
            device_limits,
            device_queue: Arc::new(arc_swap::ArcSwap::new(Arc::new((device, queue)))),
            dispatch_arena: DispatchArena::new(),
            persistent_pool: Arc::new(arc_swap::ArcSwap::new(Arc::new(persistent_pool))),
            pipeline_cache: Arc::new(runtime::cache::pipeline::LruPipelineCache::new(
                crate::pipeline::MAX_PIPELINE_CACHE_ENTRIES as u32,
            )),
            validation_cache: Arc::new(dashmap::DashSet::new()),
            device_lost: Arc::new(AtomicBool::new(false)),
            enabled_features,
        })
    }

    pub(crate) fn current_device_queue(&self) -> Arc<(wgpu::Device, wgpu::Queue)> {
        // V7-PERF-011: lock-free atomic load via ArcSwap.
        self.device_queue.load_full()
    }

    /// Consumer-visible snapshot of the live wgpu device + queue.
    ///
    /// Returns an `Arc<(Device, Queue)>` stable for the lifetime of
    /// the call; the backend may rotate the underlying pair on
    /// device-lost recovery between calls. Hold the Arc only as long
    /// as needed so recovery can drop the old pair promptly.
    #[must_use]
    pub fn device_queue(&self) -> Arc<(wgpu::Device, wgpu::Queue)> {
        self.current_device_queue()
    }

    pub(crate) fn current_persistent_pool(&self) -> crate::buffer::BufferPool {
        self.persistent_pool.load_full().as_ref().clone()
    }

    /// Test-only hook that marks the backend device as lost and invalidates
    /// caches tied to the current device generation.
    ///
    /// # Errors
    ///
    /// Returns a backend error if cache invalidation cannot complete.
    pub fn force_device_lost(&self) -> Result<(), vyre::BackendError> {
        self.device_lost.store(true, Ordering::Release);
        self.pipeline_cache.clear();
        self.validation_cache.clear();
        Ok(())
    }

    /// Create the backend if a GPU adapter is available.
    #[must_use]
    #[inline]
    pub fn new() -> Result<Self, vyre::BackendError> {
        Self::acquire().map_err(|e| vyre::BackendError::new(e.to_string()))
    }

    /// Process-wide shared backend handle. Constructs the backend on
    /// first call, then returns the same `Arc<Self>` on every
    /// subsequent call so consumers (keyhog, surgec, the conformance
    /// harness) avoid the multi-second `Self::acquire` adapter
    /// enumeration on every `scan()` invocation.
    ///
    /// The underlying wgpu device + queue is already singletonised via
    /// `CACHED_DEVICE`, but the `WgpuBackend` wrapper owned by each
    /// caller carries its own per-instance arena, pipeline cache, and
    /// stats counters. Sharing the wrapper itself amortises those
    /// allocations across the whole process and gives the persistent
    /// pipeline cache a single global hit-rate denominator instead of
    /// one per caller.
    ///
    /// # Errors
    ///
    /// Returns the same `BackendError` `Self::new()` would return if
    /// the GPU is unavailable. Once a successful backend is cached the
    /// shared handle is returned on every subsequent call without re-
    /// running adapter enumeration.
    pub fn shared() -> Result<Arc<Self>, vyre::BackendError> {
        static SHARED: std::sync::OnceLock<Result<Arc<WgpuBackend>, String>> =
            std::sync::OnceLock::new();
        match SHARED.get_or_init(|| Self::new().map(Arc::new).map_err(|e| e.to_string())) {
            Ok(arc) => Ok(arc.clone()),
            Err(msg) => Err(vyre::BackendError::new(msg.clone())),
        }
    }

    /// Dispatch a batch of `(Program, inputs, config)` triples and
    /// return their outputs in input order. Each dispatch is launched
    /// asynchronously up front and then awaited in sequence so the
    /// queue can keep multiple compute-pass submissions in flight at
    /// once — useful when keyhog needs to run literal-set + post-
    /// process + entropy in the same scan tick without the host
    /// stalling between every dispatch.
    ///
    /// The order of `Result` entries in the returned `Vec` matches the
    /// order of the input slice. A failure in one dispatch does not
    /// abort the whole batch — every job's outcome is reported
    /// individually so callers can fail-fast or surface partial
    /// dispatch diagnostics without hiding which GPU job failed.
    ///
    /// # Errors
    ///
    /// Returns the outer `BackendError` only if the *initial* async
    /// launch of any dispatch fails before any GPU work could be
    /// queued. Per-dispatch GPU failures arrive inside the inner
    /// `Result<Vec<Vec<u8>>, BackendError>` per element.
    pub fn dispatch_batch(
        &self,
        jobs: &[(vyre::Program, Vec<Vec<u8>>, vyre::DispatchConfig)],
    ) -> Result<Vec<Result<Vec<Vec<u8>>, vyre::BackendError>>, vyre::BackendError> {
        let _span =
            tracing::trace_span!("vyre.dispatch_batch", backend = "wgpu", jobs = jobs.len(),);
        let _enter = _span.enter();

        // Phase 1: launch every dispatch async. This pushes all
        // command buffers onto the queue without waiting on any of
        // them, so the GPU can begin executing the first while we
        // upload buffers for the rest.
        let mut pending = Vec::with_capacity(jobs.len());
        for (program, inputs, config) in jobs {
            let pd = self.dispatch_owned_async(
                program.clone(),
                inputs.clone(),
                config.clone(),
                Instant::now(),
            )?;
            pending.push(pd);
        }

        // Phase 2: collect each in order. Any per-dispatch GPU failure
        // is captured into the per-element Result so the caller can
        // decide whether one bad dispatch should poison the batch.
        let mut results = Vec::with_capacity(pending.len());
        for pd in pending {
            results.push(pd.await_owned());
        }
        Ok(results)
    }

    /// Compile a program into a host-ingress wgpu stream.
    ///
    /// This is not VYRE's canonical streaming model. It is a compatibility
    /// adapter for callers whose bytes still arrive through host memory. The
    /// canonical device-resident stream is the megakernel ring/IO queue in
    /// `vyre-runtime`, where the CPU launches or publishes descriptors and
    /// the GPU owns execution and phase progression.
    ///
    /// # Errors
    ///
    /// Returns a backend error when WGSL lowering or pipeline compilation fails.
    #[allow(deprecated)]
    pub fn compile_streaming(
        &self,
        program: &vyre::Program,
        config: vyre::DispatchConfig,
    ) -> Result<engine::streaming::StreamingDispatch, vyre::BackendError> {
        let pipeline = pipeline::WgpuPipeline::compile_with_device_queue(
            program,
            &config,
            self.adapter_info.clone(),
            self.enabled_features,
            self.current_device_queue(),
            self.dispatch_arena.clone(),
            self.current_persistent_pool(),
            self.pipeline_cache.clone(),
        )?;
        Ok(engine::streaming::HostIngressStream::new(
            (*pipeline).clone(),
            config,
        ))
    }

    /// Compile a program into a persistent pipeline bound to this backend's
    /// device, queue, buffer pool, and pipeline cache.
    ///
    /// # Errors
    ///
    /// Returns a backend error when validation, lowering, or pipeline
    /// compilation fails.
    pub fn compile_persistent(
        &self,
        program: &vyre::Program,
        config: &vyre::DispatchConfig,
    ) -> Result<Arc<crate::pipeline::WgpuPipeline>, vyre::BackendError> {
        pipeline::WgpuPipeline::compile_with_device_queue(
            program,
            config,
            self.adapter_info.clone(),
            self.enabled_features,
            self.current_device_queue(),
            self.dispatch_arena.clone(),
            self.current_persistent_pool(),
            self.pipeline_cache.clone(),
        )
    }

    pub(crate) fn validate_with_cache(
        &self,
        program: &vyre::Program,
    ) -> Result<(), vyre::BackendError> {
        // Backend-specific validation cache: avoids re-evaluating backend capability checks
        // (e.g. subgroup compatibility) for programs that have already passed them on this device.
        let hash = blake3::Hash::from(program.fingerprint());

        if self.validation_cache.contains(&hash) || program.is_validated_on(VyreBackend::id(self)) {
            return Ok(());
        }

        vyre_driver::backend::validation::validate_program(program, self).map_err(|error| {
            vyre::BackendError::InvalidProgram {
                fix: error.to_string(),
            }
        })?;

        let required = vyre_foundation::program_caps::scan(program);
        vyre_foundation::program_caps::check_backend_capabilities(
            VyreBackend::id(self),
            VyreBackend::supports_subgroup_ops(self),
            VyreBackend::supports_f16(self),
            VyreBackend::supports_bf16(self),
            VyreBackend::supports_indirect_dispatch(self),
            true,
            VyreBackend::max_workgroup_size(self),
            &required,
        )
        .map_err(|error| vyre::BackendError::InvalidProgram {
            fix: error.to_string(),
        })?;

        self.validation_cache.insert(hash);
        program.mark_validated_on(VyreBackend::id(self));
        Ok(())
    }

    /// Dispatch a canonical one-op f32 unary probe and return raw output bytes.
    ///
    /// **Parity-testing only.** This path deliberately bypasses vyre IR,
    /// validation, and the conform gate so the reference parity oracle can
    /// measure backend-vendor transcendental approximations directly. Only
    /// compiled with the `parity-testing` feature; production builds must
    /// never link this.
    ///
    /// # Errors
    ///
    /// Returns a backend error when `input` is not one f32, the op is not a
    /// supported f32 unary probe, or the WGSL dispatch/readback fails.
    #[cfg(feature = "parity-testing")]
    pub fn probe_op(
        &self,
        op: vyre::ir::UnOp,
        input: &[u8],
    ) -> Result<Vec<u8>, vyre::BackendError> {
        if input.len() != std::mem::size_of::<f32>() {
            return Err(vyre::BackendError::new(format!(
                "probe_op expects exactly 4 input bytes for one f32, got {}. Fix: pass f32::to_bits().to_le_bytes().",
                input.len()
            )));
        }

        let wgsl_body = match op {
            vyre::ir::UnOp::Sin => "sin(x)",
            vyre::ir::UnOp::Cos => "cos(x)",
            vyre::ir::UnOp::Sqrt => "sqrt(x)",
            vyre::ir::UnOp::Exp => "exp(x)",
            vyre::ir::UnOp::Log => "log(x)",
            other => {
                return Err(vyre::BackendError::new(format!(
                    "unsupported probe op {other:?}. Fix: use Sin, Cos, Sqrt, Exp, or Log for f32 scalar probes."
                )));
            }
        };

        let wgsl = format!(
            r#"
@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;
@group(0) @binding(2) var<uniform> params: vec4<u32>;

@compute @workgroup_size(1)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {{
    // Touch params.y so reflection keeps the uniform binding live; the
    // value is otherwise unused because this probe dispatches a single
    // invocation with gid.x == 0.
    if (params.y == 3735928559u) {{
        return;
    }}
    let x = bitcast<f32>(input[0]);
    let y = {wgsl_body};
    output[0] = bitcast<u32>(y);
}}
"#
        );

        self.dispatch_wgsl(&wgsl, input, std::mem::size_of::<f32>(), 1)
            .map_err(vyre::BackendError::new)
    }
}

inventory::submit! {
    vyre::BackendRegistration {
        id: "wgpu",
        factory: || WgpuBackend::acquire().map(|backend| {
            Box::new(backend) as Box<dyn vyre::VyreBackend>
        }),
        // Single registration path: the DialectRegistry (populated via
        // `inventory::submit! { OpDefRegistration::new(...) }`) is the sole
        // source of truth for what ops any backend accepts. No parallel
        // OpDef surface exists.
        supported_ops: wgpu_supported_ops,
    }
}

fn wgpu_supported_ops() -> &'static std::collections::HashSet<vyre::ir::OpId> {
    static OPS: std::sync::OnceLock<std::collections::HashSet<vyre::ir::OpId>> =
        std::sync::OnceLock::new();
    OPS.get_or_init(|| {
        let mut ops = vyre_driver::backend::validation::default_supported_ops().clone();
        ops.insert(Arc::from("vyre.node.trap"));
        ops
    })
}

// V7-EXT-021: declare router precedence inline (rank 30 — default WGSL path,
// trailed only by reference (90) and SPIR-V (20)).
inventory::submit! {
    vyre_driver::backend::BackendPrecedence {
        id: "wgpu",
        rank: 30,
    }
}

// TEST-034: wgpu owns a live dispatch stack via wgpu::Device, so the
// conform runner's `prove` oracle can execute Programs on this backend
// and compare against vyre-reference. Emission-only siblings (SPIR-V,
// photonic) deliberately skip this submission and get filtered out.
inventory::submit! {
    vyre_driver::backend::BackendCapability {
        id: "wgpu",
        dispatches: true,
    }
}

impl vyre_driver::backend::private::Sealed for crate::pipeline::WgpuPipeline {}

impl vyre_driver::backend::private::Sealed for WgpuBackend {}

impl vyre::VyreBackend for WgpuBackend {
    fn id(&self) -> &'static str {
        "wgpu"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn supported_ops(&self) -> &std::collections::HashSet<vyre::ir::OpId> {
        wgpu_supported_ops()
    }

    fn dispatch(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &vyre::DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre::BackendError> {
        self.dispatch_async(program, inputs, config)?.await_result()
    }

    fn dispatch_borrowed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &vyre::DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre::BackendError> {
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

    fn dispatch_async(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &vyre::DispatchConfig,
    ) -> Result<Box<dyn vyre_driver::backend::PendingDispatch>, vyre::BackendError> {
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

        Ok(Box::new(self.dispatch_owned_async(
            program.clone(),
            inputs.to_vec(),
            config.clone(),
            Instant::now(),
        )?))
    }

    fn compile_native(
        &self,
        program: &Program,
        config: &vyre::DispatchConfig,
    ) -> Result<Option<std::sync::Arc<dyn vyre::CompiledPipeline>>, vyre::BackendError> {
        self.validate_with_cache(program)?;
        // Pre-compile WGSL + ComputePipeline + bind-group layout. Returns
        // Some so the framework hands the cached pipeline back to the
        // caller directly instead of wrapping in a passthrough.
        let cached = crate::pipeline::WgpuPipeline::compile_with_device_queue(
            program,
            config,
            self.adapter_info.clone(),
            self.enabled_features,
            self.current_device_queue(),
            self.dispatch_arena.clone(),
            self.current_persistent_pool(),
            self.pipeline_cache.clone(),
        )?;
        Ok(Some(cached))
    }

    // ---------------------------------------------------------------
    // Capability queries. Report HONESTLY: each query answers "does
    // the lowering path emit this intrinsic AND did we enable the
    // corresponding adapter feature at device creation." Reading a
    // cached `EnabledFeatures` snapshot avoids re-probing the device
    // on the hot path.
    // ---------------------------------------------------------------

    fn supports_subgroup_ops(&self) -> bool {
        crate::capabilities::supports_subgroup_ops(&self.enabled_features)
    }

    fn supports_f16(&self) -> bool {
        // wgpu adapter may support shader_f16, but this WGSL/Naga lowering
        // path does not yet emit the required `enable f16;` directive.
        // Answer stays `false` until the lowering lands (LAW 9).
        false
    }

    fn supports_bf16(&self) -> bool {
        // wgpu 24 exposes bf16 through a separate lowering that vyre
        // does not yet emit. Answer stays `false` until the lowering
        // path lands, per LAW 9 (no "supported but broken" claims).
        false
    }

    fn supports_tensor_cores(&self) -> bool {
        // wgpu does not expose tensor-core / matrix-engine intrinsics
        // on the storage-buffer + workgroup model vyre uses today. A
        // dedicated MMA lowering would land first.
        false
    }

    fn supports_async_compute(&self) -> bool {
        // `dispatch_async` is real host-side asynchronous submission/readback,
        // but wgpu exposes a single universal queue here rather than a
        // distinct GPU async-compute queue. Do not let schedulers infer
        // concurrent GPU compute engines from the host API shape.
        false
    }

    fn supports_indirect_dispatch(&self) -> bool {
        crate::capabilities::supports_indirect_dispatch(&self.adapter_info, &self.enabled_features)
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

    // ---------------------------------------------------------------
    // Lifecycle hooks.
    // ---------------------------------------------------------------

    fn flush(&self) -> Result<(), vyre::BackendError> {
        // Submit any buffered work and block until the GPU drains.
        // `Maintain::Wait` is the synchronous form; callers that want
        // non-blocking flushes should use the dispatch_async path.
        match self.current_device_queue().0.poll(wgpu::Maintain::Wait) {
            wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => Ok(()),
        }
    }

    fn device_lost(&self) -> bool {
        self.device_lost.load(Ordering::Acquire)
    }

    fn try_recover(&self) -> Result<(), vyre::BackendError> {
        let ((device, queue), adapter_info, _enabled) = crate::runtime::init_device()
            .map_err(|error| vyre::BackendError::new(error.to_string()))?;
        let device_limits = device.limits();
        let persistent_pool = crate::buffer::BufferPool::with_tiering(
            device.clone(),
            queue.clone(),
            &vyre::DispatchConfig::default(),
            vec![
                crate::runtime::cache::CacheTier::new("hot", 1 << 24),
                crate::runtime::cache::CacheTier::new("cold", 1 << 30),
            ],
        );
        // V7-PERF-011: atomic swap of the device/queue pair.
        self.device_queue.store(Arc::new((device, queue)));
        self.persistent_pool.store(Arc::new(persistent_pool));
        self.pipeline_cache.clear();
        self.validation_cache.clear();
        self.device_lost.store(false, Ordering::Release);

        if adapter_info.name != self.adapter_info.name || device_limits != self.device_limits {
            tracing::info!(
                target: "vyre.device",
                old_adapter = %self.adapter_info.name,
                new_adapter = %adapter_info.name,
                "wgpu recovery reacquired a compatible device with changed adapter metadata"
            );
        }
        Ok(())
    }
}

/// Progressive staging: `Program -> WgpuIR -> WGSL -> pipeline`.
///
/// `WgpuIR` is the intermediate artifact returned by
/// [`WgpuBackend::compile`]. Each downstream stage (WGSL emission,
/// pipeline creation) is independently cacheable and testable.
/// Crate consumers that want to inspect or mutate the naga module
/// before pipeline creation go through this stage; standard
/// consumers use [`WgpuBackend`] directly via the `Executable`
/// trait.
pub struct WgpuIR {
    /// Cached pipeline that already embeds the naga::Module, WGSL
    /// shader source, bind-group layout, and workgroup size. Acts
    /// as the "backend IR artifact" in the
    /// `Program → WgpuIR → ShaderModule` chain.
    pub pipeline: pipeline::WgpuPipeline,
}

impl vyre::Executable for WgpuBackend {
    fn dispatch(
        &self,
        program: &vyre::Program,
        inputs: &[vyre::MemoryRef<'_>],
        config: &vyre::DispatchConfig,
    ) -> Result<Vec<vyre::Memory>, vyre::BackendError> {
        <Self as vyre::VyreBackend>::dispatch_borrowed(self, program, inputs, config)
    }
}

impl WgpuBackend {
    /// Compile a program once for repeated dispatch.
    pub fn compile(&self, program: &vyre::Program) -> Result<WgpuIR, vyre::BackendError> {
        let config = vyre::DispatchConfig::default();
        self.validate_with_cache(program)?;
        let pipeline = crate::pipeline::WgpuPipeline::compile_with_device_queue(
            program,
            &config,
            self.adapter_info.clone(),
            self.enabled_features,
            self.current_device_queue(),
            self.dispatch_arena.clone(),
            self.current_persistent_pool(),
            self.pipeline_cache.clone(),
        )?;
        Ok(WgpuIR {
            pipeline: (*pipeline).clone(),
        })
    }

    /// Dispatch a previously compiled program artifact.
    pub fn dispatch_compiled(
        &self,
        compiled: &WgpuIR,
        inputs: &[vyre::MemoryRef<'_>],
        config: &vyre::DispatchConfig,
    ) -> Result<Vec<vyre::Memory>, vyre::BackendError> {
        vyre::CompiledPipeline::dispatch_borrowed(&compiled.pipeline, inputs, config)
    }
}
