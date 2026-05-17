//! Precompiled CUDA pipeline implementation.

use std::sync::{Arc, Mutex};

use smallvec::SmallVec;
use vyre_driver::{
    backend::private, BackendError, CompiledPipeline, DispatchConfig, OutputBuffers, Resource,
};
use vyre_foundation::ir::Program;

use crate::backend::allocations::{cuda_check, DeviceAllocation, HostTransferAllocations};
use crate::backend::{CachedCudaGraph, CudaBackend, CudaDispatchPlan, ModuleCacheKey};

/// CUDA pipeline with PTX already lowered and loaded into the backend cache.
#[derive(Debug)]
pub(crate) struct CudaCompiledPipeline {
    backend: CudaBackend,
    program: Arc<Program>,
    ptx_src: Arc<str>,
    module_key: ModuleCacheKey,
    prepared: CudaDispatchPlan,
    compiled_config: DispatchConfig,
    graph_cache: Mutex<SmallVec<[CachedCudaGraph; MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE]>>,
    static_params: DeviceAllocation,
    id: String,
}

const MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE: usize = 4;

impl CudaCompiledPipeline {
    /// Construct a compiled CUDA pipeline.
    pub(crate) fn new(
        backend: CudaBackend,
        program: Arc<Program>,
        ptx_src: Arc<str>,
        module_key: ModuleCacheKey,
        config: &DispatchConfig,
        prepared: CudaDispatchPlan,
    ) -> Result<Self, BackendError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&vyre_driver::pipeline::normalized_program_cache_digest(
            &program,
        ));
        for lane in vyre_driver::program_vsa_fingerprint_words(&program) {
            hasher.update(&lane.to_le_bytes());
        }
        vyre_driver::pipeline::update_dispatch_policy_cache_hash(&mut hasher, config);
        hasher.update(ptx_src.as_bytes());
        hasher.update(&backend.ptx_target_sm().to_le_bytes());
        let warp_size = backend.warp_size().ok_or_else(|| BackendError::InvalidProgram {
            fix: "Fix: CUDA compiled-pipeline cache key requires a probed hardware warp size; repair CUDA capability probing before compiling pipelines.".to_string(),
        })?;
        hasher.update(&warp_size.to_le_bytes());
        hasher.update(&prepared.launch.element_count.to_le_bytes());
        for value in prepared.launch.workgroup {
            hasher.update(&value.to_le_bytes());
        }
        for value in prepared.launch.grid {
            hasher.update(&value.to_le_bytes());
        }
        hasher.update(&backend.pipeline_feature_flags().bits().to_le_bytes());
        let digest = hasher.finalize();
        let static_params = upload_static_launch_params(&backend, &prepared.launch.param_words)?;
        Ok(Self {
            backend,
            program,
            ptx_src,
            module_key,
            prepared,
            compiled_config: config.clone(),
            graph_cache: Mutex::new(SmallVec::new()),
            static_params,
            id: format!("cuda:{}", digest.to_hex()),
        })
    }
}

impl Drop for CudaCompiledPipeline {
    fn drop(&mut self) {
        self.backend
            .transient_pool
            .release(std::mem::take(&mut self.static_params));
    }
}

impl private::Sealed for CudaCompiledPipeline {}

impl CompiledPipeline for CudaCompiledPipeline {
    fn id(&self) -> &str {
        &self.id
    }

    fn dispatch(
        &self,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let borrowed: SmallVec<[&[u8]; 8]> = inputs.iter().map(Vec::as_slice).collect();
        self.dispatch_borrowed(&borrowed, config)
    }

    fn dispatch_borrowed(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        if !same_launch_shape(&self.compiled_config, config) {
            return self
                .backend
                .dispatch_borrowed_async_with_ptx_key(
                    &self.program,
                    inputs,
                    config,
                    &self.ptx_src,
                    self.module_key,
                )?
                .await_result();
        }
        let mut outputs = Vec::with_capacity(self.prepared.output_binding_indices.len());
        self.dispatch_borrowed_into(inputs, config, &mut outputs)?;
        Ok(outputs)
    }

    fn dispatch_borrowed_timed(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<vyre_driver::TimedDispatchResult, BackendError> {
        if !same_launch_shape(&self.compiled_config, config) {
            return self.backend.dispatch_borrowed_timed_with_ptx_key(
                &self.program,
                inputs,
                config,
                &self.ptx_src,
                self.module_key,
            );
        }
        if !cuda_graph_replay_enabled() {
            return self.backend.dispatch_borrowed_timed_with_ptx_key(
                &self.program,
                inputs,
                config,
                &self.ptx_src,
                self.module_key,
            );
        }
        let started = std::time::Instant::now();
        let mut outputs = Vec::with_capacity(self.prepared.output_binding_indices.len());
        let mut cached = match self.take_cached_graph(inputs)? {
            Some(cached) => cached,
            None => self
                .backend
                .record_cuda_graph_borrowed(&self.program, inputs, config)?,
        };
        let replay_result =
            self.backend
                .dispatch_via_cuda_graph_timed_into(&mut cached, inputs, &mut outputs);
        if replay_result.is_ok() {
            self.return_cached_graph(cached)?;
        }
        let device_ns = replay_result?;
        Ok(vyre_driver::TimedDispatchResult {
            outputs,
            wall_ns: started.elapsed().as_nanos() as u64,
            device_ns: Some(device_ns),
            enqueue_ns: None,
            wait_ns: None,
        })
    }

    fn dispatch_borrowed_into(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
        outputs: &mut OutputBuffers,
    ) -> Result<(), BackendError> {
        if !same_launch_shape(&self.compiled_config, config) {
            let result = self
                .backend
                .dispatch_borrowed_async_with_ptx_key(
                    &self.program,
                    inputs,
                    config,
                    &self.ptx_src,
                    self.module_key,
                )?
                .await_result()?;
            outputs.clear();
            reserve_target_capacity(outputs, result.len());
            outputs.extend(result);
            return Ok(());
        }
        if !cuda_graph_replay_enabled() {
            let result = self
                .backend
                .dispatch_borrowed_async_with_ptx_key(
                    &self.program,
                    inputs,
                    config,
                    &self.ptx_src,
                    self.module_key,
                )?
                .await_result()?;
            outputs.clear();
            reserve_target_capacity(outputs, result.len());
            outputs.extend(result);
            return Ok(());
        }
        let mut cached = match self.take_cached_graph(inputs)? {
            Some(cached) => cached,
            None => self
                .backend
                .record_cuda_graph_borrowed(&self.program, inputs, config)?,
        };
        let replay_result = self
            .backend
            .dispatch_via_cuda_graph_into(&mut cached, inputs, outputs);
        if replay_result.is_ok() {
            self.return_cached_graph(cached)?;
        }
        replay_result
    }

    fn dispatch_borrowed_batched(
        &self,
        batches: &[&[&[u8]]],
        config: &DispatchConfig,
    ) -> Result<Vec<OutputBuffers>, BackendError> {
        if batches.is_empty() {
            return Ok(Vec::new());
        }
        if same_launch_shape(&self.compiled_config, config)
            && batches
                .iter()
                .all(|batch| borrowed_input_shape_matches(batches[0], batch))
        {
            let mut cached = match self.take_cached_graph(batches[0])? {
                Some(cached) => cached,
                None => self
                    .backend
                    .record_cuda_graph_borrowed(&self.program, batches[0], config)?,
            };
            let mut outputs = Vec::with_capacity(batches.len());
            for inputs in batches {
                let mut item_outputs = Vec::with_capacity(cached.output_lens.len());
                self.backend
                    .dispatch_via_cuda_graph_into(&mut cached, inputs, &mut item_outputs)?;
                outputs.push(item_outputs);
            }
            self.return_cached_graph(cached)?;
            return Ok(outputs);
        }
        let mut pending = SmallVec::<[_; 8]>::with_capacity(batches.len());
        if same_launch_shape(&self.compiled_config, config) {
            for inputs in batches {
                pending.push(self.backend.dispatch_prepared_borrowed_async_with_ptx_key(
                    &self.program,
                    inputs,
                    &self.ptx_src,
                    self.module_key,
                    &self.prepared,
                )?);
            }
        } else {
            for inputs in batches {
                pending.push(self.backend.dispatch_borrowed_async_with_ptx_key(
                    &self.program,
                    inputs,
                    config,
                    &self.ptx_src,
                    self.module_key,
                )?);
            }
        }

        let mut outputs = Vec::with_capacity(pending.len());
        for dispatch in pending {
            outputs.push(dispatch.await_result()?);
        }
        Ok(outputs)
    }

    fn dispatch_persistent_handles(
        &self,
        inputs: &[Resource],
        config: &DispatchConfig,
    ) -> Result<OutputBuffers, BackendError> {
        let handles = self.backend.resident_handles_from_resources(inputs)?;
        if same_launch_shape(&self.compiled_config, config) {
            let resident_dispatch = self.backend.dispatch_resident_async_concrete_with_ptx_key(
                &self.program,
                &handles,
                config,
                &self.ptx_src,
                self.module_key,
                false,
                (self.static_params.ptr != 0).then_some(self.static_params.ptr),
                &self.prepared,
            )?;
            let output_handles = resident_dispatch.output_handles;
            let output_readbacks = resident_dispatch.output_readbacks;
            resident_dispatch.pending.await_timed_result()?;
            return self
                .backend
                .download_resident_readbacks_many(&output_handles, &output_readbacks);
        }
        self.backend.dispatch_resident_outputs_with_ptx_key(
            &self.program,
            &handles,
            config,
            &self.ptx_src,
            self.module_key,
        )
    }

    fn dispatch_persistent_handles_batched(
        &self,
        batches: &[&[Resource]],
        config: &DispatchConfig,
    ) -> Result<Vec<OutputBuffers>, BackendError> {
        if batches.is_empty() {
            return Ok(Vec::new());
        }
        if !same_launch_shape(&self.compiled_config, config) {
            let mut outputs = Vec::with_capacity(batches.len());
            for batch in batches {
                outputs.push(self.dispatch_persistent_handles(batch, config)?);
            }
            return Ok(outputs);
        }

        let mut resident_batches = SmallVec::<[SmallVec<[crate::backend::CudaResidentBuffer; 8]>; 8]>::with_capacity(batches.len());
        for batch in batches {
            resident_batches.push(self.backend.resident_handles_from_resources(batch)?);
        }

        let resident_dispatch = self.backend.dispatch_resident_batch_async_concrete_with_ptx_key(
            &self.program,
            &resident_batches,
            config,
            &self.ptx_src,
            self.module_key,
            (self.static_params.ptr != 0).then_some(self.static_params.ptr),
            &self.prepared,
        )?;
        let output_handles = resident_dispatch.output_handles;
        let output_readbacks = resident_dispatch.output_readbacks;
        resident_dispatch.pending.await_timed_result()?;
        self.backend
            .download_resident_readback_batches_many(&output_handles, &output_readbacks)
    }
}

impl CudaCompiledPipeline {
    fn take_cached_graph(&self, inputs: &[&[u8]]) -> Result<Option<CachedCudaGraph>, BackendError> {
        let mut graphs = self.graph_cache.lock().map_err(|_| {
            BackendError::DispatchFailed {
                code: None,
                message: "CUDA compiled-pipeline graph cache lock poisoned. Fix: rebuild the compiled pipeline after a panic during graph replay.".to_string(),
            }
        })?;
        Ok(graphs
            .iter()
            .position(|cached| cached.input_shape_matches(inputs))
            .map(|index| graphs.swap_remove(index)))
    }

    fn return_cached_graph(&self, cached: CachedCudaGraph) -> Result<(), BackendError> {
        let mut graphs = self.graph_cache.lock().map_err(|_| {
            BackendError::DispatchFailed {
                code: None,
                message: "CUDA compiled-pipeline graph cache lock poisoned while returning a graph. Fix: rebuild the compiled pipeline after a panic during graph replay.".to_string(),
            }
        })?;
        if graphs.len() < MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE {
            graphs.push(cached);
        }
        Ok(())
    }
}

fn reserve_target_capacity<T>(out: &mut Vec<T>, target_capacity: usize) {
    if out.capacity() < target_capacity {
        out.reserve_exact(target_capacity);
    }
}

fn borrowed_input_shape_matches(left: &[&[u8]], right: &[&[u8]]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(left, right)| left.len() == right.len())
}

fn upload_static_launch_params(
    backend: &CudaBackend,
    param_words: &[u32],
) -> Result<DeviceAllocation, BackendError> {
    if param_words.is_empty() {
        return Ok(DeviceAllocation::default());
    }
    let param_bytes = std::mem::size_of_val(param_words);
    let allocation = backend.transient_pool.acquire(param_bytes)?;
    let stream = match backend.launch_resources.acquire_stream() {
        Ok(stream) => stream,
        Err(err) => {
            backend.transient_pool.release(allocation);
            return Err(err);
        }
    };
    let mut host_transfers =
        HostTransferAllocations::with_capacity(std::sync::Arc::clone(&backend.host_pool), 1, 0);
    let param_host_ptr = match host_transfers.push_u32_words(param_words) {
        Ok(ptr) => ptr,
        Err(err) => {
            backend.launch_resources.release_stream(stream);
            backend.transient_pool.release(allocation);
            return Err(err);
        }
    };
    let copy_result = unsafe {
        cuda_check(
            cudarc::driver::sys::cuMemcpyHtoDAsync_v2(
                allocation.ptr,
                param_host_ptr,
                param_bytes,
                stream.raw(),
            ),
            "cuMemcpyHtoDAsync_v2",
        )
    };
    if let Err(err) = copy_result {
        backend.launch_resources.release_stream(stream);
        backend.transient_pool.release(allocation);
        return Err(err);
    }
    let sync_result = stream.synchronize();
    backend.launch_resources.release_stream(stream);
    if let Err(err) = sync_result {
        backend.transient_pool.release(allocation);
        return Err(err);
    }
    Ok(allocation)
}

fn same_launch_shape(compiled: &DispatchConfig, runtime: &DispatchConfig) -> bool {
    compiled.profile == runtime.profile
        && compiled.ulp_budget == runtime.ulp_budget
        && compiled.max_output_bytes == runtime.max_output_bytes
        && compiled.workgroup_override == runtime.workgroup_override
        && compiled.grid_override == runtime.grid_override
        && compiled.fixpoint_iterations == runtime.fixpoint_iterations
        && compiled.speculation == runtime.speculation
        && compiled.persistent_thread == runtime.persistent_thread
        && compiled.cooperative == runtime.cooperative
}

fn cuda_graph_replay_enabled() -> bool {
    std::env::var_os("VYRE_CUDA_GRAPH_REPLAY").is_some()
}
