//! CUDA backend: device lifecycle, buffer management, and kernel dispatch.

use std::sync::{Arc, Mutex};

use cudarc::driver::CudaContext;
use smallvec::SmallVec;
use vyre_driver::binding::{BindingPlan, BindingRole};
use vyre_driver::speculate::SpeculationMode;
use vyre_driver::validation::ValidationCache;
use vyre_driver::{BackendError, DispatchConfig, LaunchPlan};
use vyre_foundation::ir::Program;

use super::allocations::{DeviceAllocationPool, PinnedHostAllocationPool};
use super::module_cache::{
    CudaModuleCache, CudaPtxSourceCache, CudaPtxSourceCacheSnapshot, ModuleCacheKey,
};
use super::plan::{compute_ordered_output_indices, CudaDispatchPlan};
use super::ptx_target::select_loadable_ptx_target_sm;
use super::resident::{CudaResidentBuffer, CudaResidentStore, ResidentBufferView};
use crate::device::CudaDeviceCaps;

const TRANSIENT_ALLOCATION_POOL_BYTES: usize = 256 * 1024 * 1024;
const PINNED_HOST_POOL_BYTES: usize = 128 * 1024 * 1024;
const CUDA_LAUNCH_RESOURCE_CACHE: usize = 128;

/// A live CUDA backend handle bound to a specific device.
#[derive(Debug, Clone)]
pub struct CudaBackend {
    /// Probed device capabilities over the hardware limit.
    pub caps: CudaDeviceCaps,
    pub(crate) ptx_target_sm: u32,
    pub(crate) launch_resources: Arc<crate::stream::CudaLaunchResourcePool>,
    pub(crate) transient_pool: Arc<DeviceAllocationPool>,
    pub(crate) host_pool: Arc<PinnedHostAllocationPool>,
    pub(crate) ptx_source_cache: Arc<CudaPtxSourceCache>,
    module_cache: Arc<CudaModuleCache>,
    pub(crate) resident_store: Arc<CudaResidentStore>,
    pub(crate) validation_cache: Arc<ValidationCache>,
    pub(crate) graph_capture_lock: Arc<Mutex<()>>,
    pub(crate) ctx: Arc<CudaContext>,
}

impl CudaBackend {
    /// Acquire the default CUDA device (ordinal 0).
    pub fn acquire() -> Result<Self, String> {
        Self::acquire_ordinal(0)
    }

    /// Acquire a specific CUDA device by ordinal.
    ///
    /// # Errors
    ///
    /// Returns an error when the CUDA driver cannot initialize, the ordinal is
    /// out of range, or required device attributes cannot be queried.
    pub fn acquire_ordinal(ordinal: usize) -> Result<Self, String> {
        // E4 + E5: enable the CUDA driver's persistent disk JIT cache
        // before any module load so the first dispatch this process
        // does on a previously-seen kernel hits the on-disk cuBIN
        // instead of re-JITing. Idempotent and respectful of operator
        // overrides via the CUDA_CACHE_* env vars.
        crate::jit_cache::configure_jit_cache_default();
        let caps = CudaDeviceCaps::probe(ordinal)?;
        let ctx =
            CudaContext::new(ordinal).map_err(|e| format!("CUDA context init failed: {e}"))?;
        ctx.bind_to_thread()
            .map_err(|e| format!("CUDA context bind failed during PTX target probe: {e}"))?;
        let ptx_target_sm = select_loadable_ptx_target_sm(caps.ptx_target_sm())?;
        Ok(Self {
            caps,
            ptx_target_sm,
            launch_resources: Arc::new(crate::stream::CudaLaunchResourcePool::new(
                CUDA_LAUNCH_RESOURCE_CACHE,
            )),
            transient_pool: Arc::new(DeviceAllocationPool::new(TRANSIENT_ALLOCATION_POOL_BYTES)),
            host_pool: Arc::new(PinnedHostAllocationPool::new(PINNED_HOST_POOL_BYTES)),
            ptx_source_cache: Arc::new(CudaPtxSourceCache::new()),
            module_cache: Arc::new(CudaModuleCache::new()),
            resident_store: Arc::new(CudaResidentStore::new()),
            validation_cache: Arc::new(ValidationCache::default()),
            graph_capture_lock: Arc::new(Mutex::new(())),
            ctx,
        })
    }

    fn prepare_launch_plan(
        &self,
        program: &Program,
        bindings: &BindingPlan,
        config: &DispatchConfig,
    ) -> Result<LaunchPlan, BackendError> {
        self.enforce_config_caps(config)?;
        LaunchPlan::from_bindings(program, &bindings.bindings, config, self.launch_limits())
    }

    pub(crate) fn prepare_host_dispatch(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<CudaDispatchPlan, BackendError> {
        let bindings = BindingPlan::from_borrowed_inputs(program, inputs)?;
        let launch = self.prepare_launch_plan(program, &bindings, config)?;
        self.validate_program_cached(program)?;
        let cooperative = self.resolve_cooperative_flag(config)?;
        let output_binding_indices = compute_ordered_output_indices(&bindings);
        let fixpoint_iterations = config.fixpoint_iterations.unwrap_or(1).max(1);
        Ok(CudaDispatchPlan {
            bindings,
            output_binding_indices,
            launch,
            cooperative,
            fixpoint_iterations,
        })
    }

    pub(crate) fn prepare_static_dispatch(
        &self,
        program: &Program,
        config: &DispatchConfig,
    ) -> Result<CudaDispatchPlan, BackendError> {
        let bindings = BindingPlan::build(program)?;
        let launch = self.prepare_launch_plan(program, &bindings, config)?;
        self.validate_program_cached(program)?;
        let cooperative = self.resolve_cooperative_flag(config)?;
        let output_binding_indices = compute_ordered_output_indices(&bindings);
        let fixpoint_iterations = config.fixpoint_iterations.unwrap_or(1).max(1);
        Ok(CudaDispatchPlan {
            bindings,
            output_binding_indices,
            launch,
            cooperative,
            fixpoint_iterations,
        })
    }

    pub(crate) fn prepare_resident_dispatch(
        &self,
        program: &Program,
        handles: &[CudaResidentBuffer],
        config: &DispatchConfig,
    ) -> Result<CudaDispatchPlan, BackendError> {
        let static_bindings = BindingPlan::build(program)?;
        let required_handles = static_bindings
            .bindings
            .iter()
            .filter(|binding| binding.role != BindingRole::Shared)
            .count();
        if handles.len() != required_handles {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident dispatch expected {required_handles} resident buffer handle(s) but received {}.",
                    handles.len()
                ),
            });
        }

        let mut input_lengths =
            SmallVec::<[usize; 8]>::with_capacity(static_bindings.input_indices.len());
        input_lengths.resize(static_bindings.input_indices.len(), 0);
        let mut next_handle = 0usize;
        for binding in &static_bindings.bindings {
            if binding.role == BindingRole::Shared {
                continue;
            }
            let handle = handles[next_handle];
            next_handle += 1;
            let resident = self.resident_store.view(handle)?;
            if let Some(input_index) = binding.input_index {
                input_lengths[input_index] = resident.byte_len;
            }
        }

        let bindings = BindingPlan::from_input_lengths(program, &input_lengths)?;
        let launch = self.prepare_launch_plan(program, &bindings, config)?;
        self.validate_program_cached(program)?;
        let cooperative = self.resolve_cooperative_flag(config)?;
        let output_binding_indices = compute_ordered_output_indices(&bindings);
        let fixpoint_iterations = config.fixpoint_iterations.unwrap_or(1).max(1);
        Ok(CudaDispatchPlan {
            bindings,
            output_binding_indices,
            launch,
            cooperative,
            fixpoint_iterations,
        })
    }

    /// Validate that the caller's cooperative-launch request is consistent
    /// with the device's reported capabilities. Returns the resolved flag
    /// (always `false` when the caller didn't ask) or an `UnsupportedFeature`
    /// error when the caller asked for cooperative launch on a device that
    /// can't run it.
    ///
    /// This method gates *only* the host-side launch API, NOT the codegen
    /// emission of in-kernel grid-sync barriers. The barrier emission is
    /// still controlled by `lowers_grid_sync()`. Callers that opt into
    /// cooperative launch but whose program does not contain any GridSync
    /// barriers get the cooperative API call (resident grid) but no
    /// in-kernel sync sequence — the launcher still runs faster on programs
    /// that benefit from a resident grid even without explicit grid-sync.
    fn resolve_cooperative_flag(&self, config: &DispatchConfig) -> Result<bool, BackendError> {
        if !config.cooperative {
            return Ok(false);
        }
        if !self.hardware_supports_grid_sync() {
            return Err(BackendError::UnsupportedFeature {
                name: format!(
                    "cuda_cooperative_launch (compute_capability={:?}, cooperative_launch={})",
                    self.caps.compute_capability, self.caps.cooperative_launch
                ),
                backend: crate::CUDA_BACKEND_ID.to_string(),
            });
        }
        Ok(true)
    }

    fn enforce_config_caps(&self, config: &DispatchConfig) -> Result<(), BackendError> {
        if matches!(config.speculation, Some(SpeculationMode::Force)) {
            return Err(BackendError::UnsupportedFeature {
                name: "speculative dispatch".to_string(),
                backend: crate::CUDA_BACKEND_ID.to_string(),
            });
        }
        Ok(())
    }

    /// Pre-warmup: ensures the CUDA context is active.
    pub fn warmup(&self) -> Result<(), BackendError> {
        self.ctx
            .bind_to_thread()
            .map_err(|e| BackendError::DispatchFailed {
                code: None,
                message: format!("CUDA context bind failed: {e}"),
            })
    }

    /// Cleanup: sync and release cached modules.
    pub fn cleanup(&self) -> Result<(), BackendError> {
        self.warmup()?;
        self.ptx_source_cache.clear();
        self.module_cache.clear();
        self.resident_store.clear()?;
        self.transient_pool.clear()?;
        self.host_pool.clear()?;
        self.launch_resources.clear()?;
        Ok(())
    }

    pub(crate) fn with_resident<T>(
        &self,
        handle: CudaResidentBuffer,
        f: impl FnOnce(ResidentBufferView) -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        self.warmup()?;
        let buffer = self.resident_store.view(handle)?;
        f(buffer)
    }

    pub(crate) fn resident_handles_from_resources(
        &self,
        resources: &[vyre_driver::Resource],
    ) -> Result<SmallVec<[CudaResidentBuffer; 8]>, BackendError> {
        self.resident_store.handles_from_resources(resources)
    }

    pub(crate) fn module_cache_key(&self, ptx_src: &str) -> ModuleCacheKey {
        self.module_cache
            .key_for_ptx(ptx_src, self.caps.compute_capability)
    }

    pub(crate) fn module_for_ptx_with_key(
        &self,
        ptx_src: &str,
        key: ModuleCacheKey,
    ) -> Result<cudarc::driver::sys::CUfunction, BackendError> {
        self.module_cache
            .function_for_ptx(ptx_src, key, self.ptx_target_sm())
    }

    /// Number of loaded CUDA modules currently held in the warm cache.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the cache lock is poisoned.
    pub fn cached_module_count(&self) -> Result<usize, BackendError> {
        Ok(self.module_cache.len())
    }

    /// Compiled module cache counters for honest compile telemetry.
    #[must_use]
    pub fn pipeline_cache_snapshot(&self) -> vyre_driver::pipeline::PipelineCacheSnapshot {
        self.module_cache.snapshot()
    }

    /// PTX source cache counters for pre-module-load lowering telemetry.
    #[must_use]
    pub fn ptx_source_cache_snapshot(&self) -> CudaPtxSourceCacheSnapshot {
        self.ptx_source_cache.snapshot()
    }

    /// Bytes of transient CUDA device memory retained for dispatch reuse.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the allocation-pool lock is poisoned.
    pub fn cached_transient_allocation_bytes(&self) -> Result<usize, BackendError> {
        self.transient_pool.cached_bytes()
    }

    /// Cached CUDA streams/events retained for dispatch reuse.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if a launch-resource pool lock is poisoned.
    pub fn cached_launch_resource_counts(&self) -> Result<(usize, usize), BackendError> {
        self.launch_resources.cached_counts()
    }

    /// Snapshot the driver-tier observability surface
    /// ([`vyre_driver::observability::DriverObservability`]) plus the
    /// cuda module-cache count as a single backend metric.
    ///
    /// Operators scrape this in addition to per-substrate Prometheus
    /// counters when correlating substrate activity with backend
    /// resource usage.
    #[must_use]
    pub fn observability_snapshot(&self) -> vyre_driver::observability::DriverObservability {
        vyre_driver::observability::DriverObservability::snapshot()
    }

    /// PTX disk-cache directory path. Reuses the same on-disk layout
    /// vyre-driver-wgpu uses for its pipeline cache, keyed by the shared
    /// VSA fingerprint.
    ///
    /// P-CUDA-2: PTX/CUBIN blobs persist across runs in this directory
    /// so first-run compile cost amortizes over the cluster.
    #[must_use]
    pub fn ptx_disk_cache_dir() -> std::path::PathBuf {
        std::env::var_os("VYRE_PTX_CACHE_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("vyre-ptx-cache"))
    }

    /// Pre-lower and preload a CUDA pipeline for repeated dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when PTX lowering or CUDA module loading fails.
    pub fn compile_native(
        &self,
        program: &Program,
        config: &DispatchConfig,
    ) -> Result<std::sync::Arc<dyn vyre_driver::CompiledPipeline>, BackendError> {
        self.compile_native_shared(std::sync::Arc::new(program.clone()), config)
    }

    /// Pre-lower and preload a CUDA pipeline while preserving a caller-owned
    /// shared program allocation.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when PTX lowering or CUDA module loading fails.
    pub fn compile_native_shared(
        &self,
        program: std::sync::Arc<Program>,
        config: &DispatchConfig,
    ) -> Result<std::sync::Arc<dyn vyre_driver::CompiledPipeline>, BackendError> {
        let prepared = self.prepare_static_dispatch(program.as_ref(), config)?;
        let ptx_src = self.ptx_for_program_cached(program.as_ref(), config)?;
        let module_key = self.module_cache_key(&ptx_src);
        self.warmup()?;
        self.module_for_ptx_with_key(&ptx_src, module_key)?;
        Ok(std::sync::Arc::new(
            crate::pipeline::CudaCompiledPipeline::new(
                self.clone(),
                program,
                ptx_src,
                module_key,
                config,
                prepared,
            )?,
        ))
    }
}
