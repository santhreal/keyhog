//! # vyre-driver-cuda — CUDA/PTX backend for vyre
//!
//! Implements [`VyreBackend`] via the CUDA driver API through `cudarc`.
//! Translates vyre `Program` IR into PTX kernels, loads them through
//! the CUDA driver JIT, and dispatches on NVIDIA GPUs.
//!
//! The backend registers itself as `"cuda"` in the vyre backend registry
//! via `inventory::submit!` so `vyre::registered_backends()` enumerates
//! it alongside `wgpu`, `spirv`, etc.
//!
//! ## Architecture
//!
//! ```text
//!    Program ─► PTX emitter ─► cuModuleLoadData ─► cuLaunchKernel
//! ```
//!
#![deny(missing_docs)]
// CUDA driver bindings (`cudarc::driver::sys::cu*`) are inherently unsafe FFI;
// every call site is the boundary between safe vyre code and the CUDA driver
// API. Allow `unsafe` here so the rest of the workspace can keep
// `unsafe_code = "deny"` while this backend wraps cudarc properly with
// per-call Safety: comments enforced by `check_unsafe_justifications.sh`.
#![allow(unsafe_code)]

mod aot_launcher;
/// CUDA backend core: device management and dispatch.
pub mod backend;
/// PTX code generation from vyre IR.
pub mod codegen;
/// CUDA device capability probing.
pub mod device;
/// Cross-process persistent CUDA JIT cache wiring (E4 + E5): configures
/// the NVIDIA driver's built-in disk cache at backend bring-up so the
/// JIT-compiled cuBINs persist across runs and are shared across every
/// vyre process on the host.
pub mod jit_cache;
/// Occupancy-aware empirical autotuning (I4): pure estimator that picks
/// the workgroup size with the highest predicted hardware occupancy from
/// `(CudaDeviceCaps, KernelResourceUsage)`. The runtime feeds the result
/// into `AutotuneStore` (I3) so subsequent dispatches reuse the choice.
pub mod occupancy;
mod pipeline;
mod stream;

pub use backend::{CudaBackend, CudaPtxSourceCacheSnapshot, CudaResidentBuffer};
pub use device::CudaDeviceCaps;

use std::sync::Arc;

use smallvec::SmallVec;
use vyre_driver::{BackendError, BackendRegistration, DispatchConfig, Resource, VyreBackend};
use vyre_foundation::ir::Program;

/// Stable backend identifier for registration and conform certificates.
pub const CUDA_BACKEND_ID: &str = "cuda";

/// Factory wrapper for the inventory registration path.
///
/// Unlike the SPIR-V backend, the CUDA backend owns a live device handle
/// and can dispatch programs directly.
#[derive(Debug)]
pub struct CudaBackendRegistration {
    inner: CudaBackend,
}

impl CudaBackendRegistration {
    /// Wrap an already-acquired [`CudaBackend`] as a [`VyreBackend`] trait object.
    ///
    /// The inventory-driven path uses [`cuda_factory`] which acquires its own
    /// device handle. Callers that already own a [`CudaBackend`] (e.g. so they
    /// can keep the live device handle for direct API access while also handing
    /// it to a megakernel) use this constructor instead.
    #[must_use]
    pub fn new(inner: CudaBackend) -> Self {
        Self { inner }
    }

    /// Borrow the inner [`CudaBackend`] for direct device-API access.
    #[must_use]
    pub fn inner(&self) -> &CudaBackend {
        &self.inner
    }

    /// Snapshot the CUDA PTX-source cache used before driver module loading.
    #[must_use]
    pub fn ptx_source_cache_snapshot(&self) -> CudaPtxSourceCacheSnapshot {
        self.inner.ptx_source_cache_snapshot()
    }
}

impl vyre_driver::backend::private::Sealed for CudaBackendRegistration {}

impl VyreBackend for CudaBackendRegistration {
    fn id(&self) -> &'static str {
        CUDA_BACKEND_ID
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn dispatch(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        if vyre_driver::grid_sync::contains_grid_sync(program) && !self.supports_grid_sync() {
            let borrowed: SmallVec<[&[u8]; 8]> = inputs.iter().map(Vec::as_slice).collect();
            return vyre_driver::grid_sync::dispatch_with_grid_sync_split(
                self, program, &borrowed, config,
            );
        }
        self.inner.dispatch(program, inputs, config)
    }

    fn dispatch_async(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Box<dyn vyre_driver::PendingDispatch>, BackendError> {
        self.inner.dispatch_async(program, inputs, config)
    }

    fn dispatch_borrowed_async(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Box<dyn vyre_driver::PendingDispatch>, BackendError> {
        self.inner.dispatch_borrowed_async(program, inputs, config)
    }

    fn dispatch_borrowed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        if vyre_driver::grid_sync::contains_grid_sync(program) && !self.supports_grid_sync() {
            return vyre_driver::grid_sync::dispatch_with_grid_sync_split(
                self, program, inputs, config,
            );
        }
        self.inner
            .dispatch_borrowed_async(program, inputs, config)?
            .await_result()
    }

    fn dispatch_borrowed_timed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<vyre_driver::TimedDispatchResult, BackendError> {
        if vyre_driver::grid_sync::contains_grid_sync(program) && !self.supports_grid_sync() {
            return vyre_driver::grid_sync::dispatch_with_grid_sync_split_timed(
                self, program, inputs, config,
            );
        }
        self.inner.dispatch_borrowed_timed(program, inputs, config)
    }

    fn allocate_resident(&self, byte_len: usize) -> Result<Resource, BackendError> {
        self.inner
            .allocate_resident(byte_len)
            .map(|handle| Resource::Resident(handle.id))
    }

    fn upload_resident(&self, resource: &Resource, bytes: &[u8]) -> Result<(), BackendError> {
        let handle = self
            .inner
            .resident_handles_from_resources(std::slice::from_ref(resource))?
            .into_iter()
            .next()
            .ok_or_else(|| BackendError::InvalidProgram {
                fix: "Fix: CUDA resident upload requires exactly one resident resource handle."
                    .to_string(),
            })?;
        self.inner.upload_resident(handle, bytes)
    }

    fn free_resident(&self, resource: Resource) -> Result<(), BackendError> {
        let handle = self
            .inner
            .resident_handles_from_resources(std::slice::from_ref(&resource))?
            .into_iter()
            .next()
            .ok_or_else(|| BackendError::InvalidProgram {
                fix: "Fix: CUDA resident free requires exactly one resident resource handle."
                    .to_string(),
            })?;
        self.inner.free_resident(handle)
    }

    fn dispatch_resident_timed(
        &self,
        program: &Program,
        resources: &[Resource],
        config: &DispatchConfig,
    ) -> Result<vyre_driver::TimedDispatchResult, BackendError> {
        let handles = self.inner.resident_handles_from_resources(resources)?;
        self.inner
            .dispatch_resident_timed(program, &handles, config)
    }

    fn compile_native(
        &self,
        program: &Program,
        config: &DispatchConfig,
    ) -> Result<Option<Arc<dyn vyre_driver::CompiledPipeline>>, BackendError> {
        self.inner.compile_native(program, config).map(Some)
    }

    fn compile_native_shared(
        &self,
        program: Arc<Program>,
        config: &DispatchConfig,
    ) -> Result<Option<Arc<dyn vyre_driver::CompiledPipeline>>, BackendError> {
        self.inner.compile_native_shared(program, config).map(Some)
    }

    fn pipeline_cache_snapshot(&self) -> Option<vyre_driver::pipeline::PipelineCacheSnapshot> {
        Some(self.inner.pipeline_cache_snapshot())
    }

    fn backend_metric_snapshot(&self) -> Vec<(&'static str, u64)> {
        let source_cache = self.inner.ptx_source_cache_snapshot();
        vec![
            ("cuda_ptx_source_cache_entries", source_cache.entries as u64),
            ("cuda_ptx_source_cache_hits", source_cache.hits),
            ("cuda_ptx_source_cache_misses", source_cache.misses),
        ]
    }

    fn supports_subgroup_ops(&self) -> bool {
        self.inner.hardware_supports_subgroup_ops()
    }

    fn supports_f16(&self) -> bool {
        self.inner.hardware_supports_f16()
    }

    fn supports_bf16(&self) -> bool {
        self.inner.hardware_supports_bf16()
    }

    fn supports_tensor_cores(&self) -> bool {
        self.inner.hardware_supports_tensor_cores() && self.inner.lowers_tensor_core_ops()
    }

    fn supports_async_compute(&self) -> bool {
        self.inner.hardware_supports_async_compute()
    }

    fn supports_grid_sync(&self) -> bool {
        self.inner.supports_grid_sync()
    }

    fn supports_speculation(&self) -> bool {
        false
    }

    fn max_workgroup_size(&self) -> [u32; 3] {
        self.inner.max_block_dim()
    }

    fn max_compute_workgroups_per_dimension(&self) -> u32 {
        self.inner.max_grid_dim()[0]
    }

    fn max_compute_invocations_per_workgroup(&self) -> u32 {
        self.inner.max_threads_per_block()
    }

    fn subgroup_size(&self) -> Option<u32> {
        self.inner.warp_size()
    }

    fn max_storage_buffer_bytes(&self) -> u64 {
        self.inner.device_memory_bytes()
    }

    fn device_profile(&self) -> vyre_driver::DeviceProfile {
        let mut profile = self.inner.caps.to_device_profile();
        profile.supports_tensor_cores = self.supports_tensor_cores();
        profile.supports_indirect_dispatch = self.supports_indirect_dispatch();
        profile
    }

    fn prepare(&self) -> Result<(), BackendError> {
        self.inner.warmup()
    }

    fn shutdown(&self) -> Result<(), BackendError> {
        self.inner.cleanup()
    }
}

/// Factory function for inventory registration.
pub fn cuda_factory() -> Result<Box<dyn VyreBackend>, BackendError> {
    let backend = CudaBackend::acquire().map_err(|e| BackendError::DispatchFailed {
        code: None,
        message: format!("CUDA backend acquisition failed: {e}"),
    })?;
    Ok(Box::new(CudaBackendRegistration { inner: backend }))
}

/// Op-support set — CUDA supports every op the foundation IR defines
/// plus hardware intrinsics. Populated at runtime by the conform runner.
pub fn cuda_supported_ops() -> &'static std::collections::HashSet<vyre_foundation::ir::OpId> {
    vyre_driver::backend::validation::default_supported_ops_with_trap()
}

inventory::submit! {
    BackendRegistration {
        id: CUDA_BACKEND_ID,
        factory: cuda_factory,
        supported_ops: cuda_supported_ops,
    }
}

// rank 5 - CUDA is the canonical release dispatch backend when linked.
inventory::submit! {
    vyre_driver::backend::BackendPrecedence {
        id: CUDA_BACKEND_ID,
        rank: 5,
    }
}

// CUDA owns a live dispatch stack, so conform can prove against it.
inventory::submit! {
    vyre_driver::backend::BackendCapability {
        id: CUDA_BACKEND_ID,
        dispatches: true,
    }
}

fn emit_aot_bytes(program: &Program, config: &DispatchConfig) -> Result<Vec<u8>, String> {
    let backend = CudaBackend::acquire().map_err(|error| {
        format!(
            "CUDA PTX AOT emission could not probe the live device target: {error}. Fix: run AOT emission on a host with the CUDA driver and target GPU visible."
        )
    })?;
    crate::codegen::program_to_ptx_for_sm_and_subgroup(
        program,
        config,
        backend.ptx_target_sm(),
        backend.warp_size().ok_or_else(|| {
            "CUDA PTX AOT emission could not read a hardware warp size from the live device probe. Fix: repair CUDA capability probing before AOT emission.".to_string()
        })?,
    )
    .map(String::into_bytes)
}

inventory::submit! {
    vyre_driver::aot::AotEmitter {
        target: "secondary_text",
        emit: emit_aot_bytes,
    }
}

inventory::submit! {
    vyre_driver::aot::AotLauncherEmitter {
        target: "secondary_text",
        emit: aot_launcher::emit_launcher,
    }
}
