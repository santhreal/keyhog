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
/// Benchmark-driven CUDA optimization pass selection.
pub mod benchmark_pass_selection;
/// PTX code generation from vyre IR.
pub mod codegen;
/// CUDA device capability probing.
pub mod device;
/// Device-side diagnostic aggregation and compact readback planning.
pub mod device_diagnostic_aggregation;
/// Device-side work queue planning for dependent dataflow.
pub mod device_work_queue;
/// Adapter from frontier-typed IR plans to CUDA frontier wave envelopes.
pub mod frontier_typed_ir_adapter;
/// Cross-process persistent CUDA JIT cache wiring (E4 + E5): configures
/// the NVIDIA driver's built-in disk cache at backend bring-up so the
/// JIT-compiled cuBINs persist across runs and are shared across every
/// vyre process on the host.
pub mod jit_cache;
/// Actionable CUDA kernel capability diagnostics.
pub mod kernel_failure_diagnostics;
/// Adjacent-stage CUDA launch fusion planning.
pub mod launch_fusion;
/// Bounded CUDA megakernel plan cache keyed by graph, analysis, device, and
/// runtime pressure buckets.
pub mod megakernel_plan_cache;
/// Multi-query CUDA execution planning over shared resident graphs.
pub mod multi_query_execution;
mod numeric;
/// Occupancy-aware empirical autotuning (I4): pure estimator that picks
/// the workgroup size with the highest predicted hardware occupancy from
/// `(CudaDeviceCaps, KernelResourceUsage)`. The runtime feeds the result
/// into `AutotuneStore` (I3) so subsequent dispatches reuse the choice.
pub mod occupancy;
/// Self-hosted optimizer GPU dispatcher — runs the
/// `vyre-self-substrate::optimizer` passes (DCE, CSE, const-fold,
/// validator) on CUDA. External parity tests reach in via the
/// `CudaOptimizerDispatcher` re-export below.
pub mod optimizer;
mod pipeline;
/// Repeated execution over persistent CUDA-resident graph state.
pub mod resident_graph_session;
/// Compact result readback planning.
pub mod result_compaction;
mod stream;
/// CUDA execution planning for unified token/fact graph frontier waves.
pub mod token_fact_frontier_execution;
/// Adapter from unified token/fact graph layouts to CUDA resident bytes.
pub mod token_fact_graph_cuda_adapter;

pub use backend::{
    CudaBackend, CudaPtxSourceCacheSnapshot, CudaResidentBuffer, CudaTelemetrySnapshot,
};
pub use benchmark_pass_selection::{
    select_cuda_benchmark_passes, select_cuda_benchmark_passes_with_scratch,
    CudaBenchmarkPassCandidate, CudaBenchmarkPassSelectionError, CudaBenchmarkPassSelectionPlan,
    CudaBenchmarkPassSelectionSample, CudaBenchmarkPassSelectionScratch,
    CudaBenchmarkPassSkipReason, CudaSkippedBenchmarkPass,
};
pub use stream::CudaLaunchResourceCounts;
/// CUDA megakernel global-barrier minimization for dependency-typed waves.
pub mod megakernel_barrier_planner;
/// CUDA megakernel convergence planning for iterative fixed-point analyses.
pub mod megakernel_convergence;
pub mod megakernel_scheduler;
/// Release gate for steady-state CUDA megakernel speedup claims.
pub mod megakernel_speedup_gate;
pub use device::{CudaDeviceCaps, CudaDeviceHandle};
pub use device_diagnostic_aggregation::{
    plan_cuda_device_diagnostic_aggregation, plan_cuda_device_diagnostic_aggregation_with_scratch,
    CudaDiagnosticAggregationError, CudaDiagnosticAggregationPlan,
    CudaDiagnosticAggregationScratch, CudaDiagnosticCompactRange, CudaDiagnosticShard,
};
pub use device_work_queue::{
    plan_cuda_device_work_queue, plan_cuda_device_work_queue_backpressure,
    CudaDeviceWorkQueueBackpressurePlan, CudaDeviceWorkQueueDrainStrategy,
    CudaDeviceWorkQueueError, CudaDeviceWorkQueuePlan, CudaDeviceWorkQueueProfile,
    CudaWorkQueueHostSync,
};
pub use frontier_typed_ir_adapter::{
    adapt_frontier_typed_ir_to_cuda, CudaFrontierTypedIrAdapterError, CudaFrontierTypedIrInput,
};
pub use kernel_failure_diagnostics::{
    diagnose_cuda_kernel_launch, diagnose_cuda_kernel_launch_shape,
    diagnose_cuda_kernel_launch_with_scratch, CudaKernelCapabilityFailure,
    CudaKernelDeviceEnvelope, CudaKernelLaunchDiagnostic, CudaKernelLaunchDiagnosticRef,
    CudaKernelLaunchDiagnosticScratch, CudaKernelLaunchEnvelope, CudaKernelLaunchEnvelopeError,
    CudaKernelLaunchShape, CudaKernelRequirement,
};
pub use launch_fusion::{
    plan_cuda_launch_fusion, plan_cuda_launch_fusion_with_scratch, CudaFusionStage,
    CudaLaunchFusionError, CudaLaunchFusionGroup, CudaLaunchFusionPlan, CudaLaunchFusionScratch,
};
pub use megakernel_barrier_planner::{
    plan_cuda_frontier_megakernel_execution, plan_cuda_frontier_megakernel_execution_with_scratch,
    plan_cuda_megakernel_barriers, plan_cuda_megakernel_barriers_with_scratch,
    CudaMegakernelBarrierGroup, CudaMegakernelBarrierPlan, CudaMegakernelBarrierPlanError,
    CudaMegakernelBarrierScratch, CudaMegakernelFrontierExecutionPlan,
    CudaMegakernelFrontierExecutionPlanError, CudaMegakernelFrontierWave,
    CudaMegakernelWaveDependency,
};
pub use megakernel_convergence::{
    plan_cuda_device_convergence, CudaConvergenceReadbackPolicy, CudaDeviceConvergencePlan,
    CudaDeviceConvergencePlanError,
};
pub use megakernel_plan_cache::{
    CudaMegakernelAnalysisKind, CudaMegakernelCachedPlan, CudaMegakernelDeviceKey,
    CudaMegakernelPlanCache, CudaMegakernelPlanCacheKey, CudaMegakernelPlanCacheStats,
};
pub use megakernel_scheduler::{
    plan_cuda_megakernel_execution, plan_cuda_megakernel_memory_budget,
    schedule_megakernel_from_cuda_samples, schedule_megakernel_from_cuda_samples_into,
    select_cuda_megakernel_topology, CudaMegakernelExecutionPlan, CudaMegakernelGraphShape,
    CudaMegakernelMemoryBudget, CudaMegakernelMemoryError, CudaMegakernelMemoryPlan,
    CudaMegakernelScheduleSample, CudaMegakernelTopology, CudaMegakernelTopologyDecision,
};
pub use megakernel_speedup_gate::{
    format_validated_cuda_megakernel_speedup_evidence_csv,
    validate_cuda_megakernel_speedup_evidence_csv, validate_cuda_megakernel_speedup_gate,
    CudaMegakernelSpeedupGateError, CudaMegakernelSpeedupProof, CudaMegakernelSpeedupSample,
    MEGAKERNEL_SPEEDUP_EVIDENCE_CSV_HEADER,
};
pub use multi_query_execution::{
    plan_cuda_multi_query_execution, plan_cuda_multi_query_execution_with_scratch, CudaMultiQuery,
    CudaMultiQueryExecutionError, CudaMultiQueryExecutionPlan, CudaMultiQueryExecutionScratch,
    CudaMultiQueryGroup,
};
pub use optimizer::CudaOptimizerDispatcher;
pub use resident_graph_session::{
    format_validated_cuda_resident_graph_session_evidence_csv, plan_cuda_resident_graph_session,
    resident_graph_session_speedup_sample, CudaResidentGraphReadback,
    CudaResidentGraphSessionError, CudaResidentGraphSessionEvidence,
    CudaResidentGraphSessionEvidenceError, CudaResidentGraphSessionPlan,
    CudaResidentGraphSessionProfile,
};
pub use result_compaction::{
    plan_cuda_result_compaction, plan_cuda_result_compaction_with_scratch, CudaCompactResultRecord,
    CudaResultCompactionError, CudaResultCompactionPlan, CudaResultCompactionScratch,
    CudaResultSlot,
};
pub use token_fact_frontier_execution::{
    plan_cuda_token_fact_frontier_execution, plan_cuda_token_fact_frontier_execution_with_scratch,
    CudaTokenFactFrontierExecutionError, CudaTokenFactFrontierExecutionPlan,
};
pub use token_fact_graph_cuda_adapter::{
    adapt_token_fact_graph_to_cuda_layout, CudaTokenFactGraphLayout, CudaTokenFactGraphLayoutError,
};

use std::sync::Arc;

use crate::backend::staging_reserve::reserve_smallvec;
use smallvec::SmallVec;
use vyre_driver::{BackendError, BackendRegistration, DispatchConfig, Resource, VyreBackend};
use vyre_foundation::ir::Program;

/// Stable backend identifier for registration and conform certificates.
pub const CUDA_BACKEND_ID: &str = "cuda";

/// CUDA implementation of [`vyre_driver::DeviceBuffer`]. Wraps a
/// [`backend::CudaResidentBuffer`] handle so consumers can hold a
/// `Box<dyn DeviceBuffer>` against the CUDA backend without naming
/// `CudaResidentBuffer` directly.
///
/// Lifecycle is explicit-free — call
/// `VyreBackend::free_device_buffer(boxed_buffer)` when done. This
/// matches the existing CUDA-resident contract and keeps the substrate
/// free of reference-counted backend handles. A future RAII variant
/// (Drop-managed via `Arc<CudaBackend>`) can ship as a drop-in
/// replacement when the backend ownership model accommodates it.
#[derive(Debug)]
pub struct CudaDeviceBuffer {
    backend_id: &'static str,
    handle: backend::CudaResidentBuffer,
}

impl vyre_driver::DeviceBuffer for CudaDeviceBuffer {
    fn backend_id(&self) -> &'static str {
        self.backend_id
    }

    fn byte_len(&self) -> usize {
        self.handle.byte_len
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

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

    /// Runtime CUDA telemetry counters for release-path performance gates.
    #[must_use]
    pub fn telemetry_snapshot(&self) -> CudaTelemetrySnapshot {
        self.inner.telemetry_snapshot()
    }

    /// Reset runtime CUDA telemetry counters without clearing backend caches.
    pub fn reset_telemetry(&self) {
        self.inner.reset_telemetry();
    }

    fn resolve_uploads<'a>(
        &self,
        uploads: &[(&Resource, &'a [u8])],
    ) -> Result<SmallVec<[(CudaResidentBuffer, &'a [u8]); 8]>, BackendError> {
        let mut concrete = SmallVec::<[(CudaResidentBuffer, &'a [u8]); 8]>::new();
        reserve_smallvec(&mut concrete, uploads.len(), "CUDA resident upload handles")?;
        for (resource, bytes) in uploads {
            let handle = self.inner.resident_handle_from_resource(resource)?;
            concrete.push((handle, *bytes));
        }
        Ok(concrete)
    }

    fn resolve_offset_uploads<'a>(
        &self,
        uploads: &[(&Resource, usize, &'a [u8])],
    ) -> Result<SmallVec<[(CudaResidentBuffer, usize, &'a [u8]); 8]>, BackendError> {
        let mut concrete = SmallVec::<[(CudaResidentBuffer, usize, &'a [u8]); 8]>::new();
        reserve_smallvec(
            &mut concrete,
            uploads.len(),
            "CUDA resident offset upload handles",
        )?;
        for (resource, dst_offset_bytes, bytes) in uploads {
            let handle = self.inner.resident_handle_from_resource(resource)?;
            concrete.push((handle, *dst_offset_bytes, *bytes));
        }
        Ok(concrete)
    }

    fn resolve_download_ranges(
        &self,
        ranges: &[(&Resource, usize, usize)],
    ) -> Result<SmallVec<[(CudaResidentBuffer, usize, usize); 8]>, BackendError> {
        let mut concrete = SmallVec::<[(CudaResidentBuffer, usize, usize); 8]>::new();
        reserve_smallvec(
            &mut concrete,
            ranges.len(),
            "CUDA resident download range handles",
        )?;
        for (resource, byte_offset, byte_len) in ranges {
            let handle = self.inner.resident_handle_from_resource(resource)?;
            concrete.push((handle, *byte_offset, *byte_len));
        }
        Ok(concrete)
    }

    fn resolve_read_ranges(
        &self,
        read_ranges: &[vyre_driver::backend::ResidentReadRange<'_>],
    ) -> Result<
        (
            SmallVec<[CudaResidentBuffer; 8]>,
            SmallVec<[crate::backend::output_range::CudaOutputReadback; 8]>,
        ),
        BackendError,
    > {
        let mut handles = SmallVec::<[CudaResidentBuffer; 8]>::new();
        let mut concrete_readbacks =
            SmallVec::<[crate::backend::output_range::CudaOutputReadback; 8]>::new();
        reserve_smallvec(
            &mut handles,
            read_ranges.len(),
            "CUDA resident read handles",
        )?;
        reserve_smallvec(
            &mut concrete_readbacks,
            read_ranges.len(),
            "CUDA resident readback ranges",
        )?;
        for range in read_ranges {
            handles.push(self.inner.resident_handle_from_resource(range.resource)?);
            concrete_readbacks.push(crate::backend::output_range::CudaOutputReadback {
                device_offset: range.byte_offset,
                byte_len: range.byte_len,
            });
        }
        Ok((handles, concrete_readbacks))
    }

    /// Bytes of transient CUDA device memory currently owned by the transient pool.
    ///
    /// This includes checked-out dispatch allocations, compiled-pipeline static parameter
    /// allocations, and cached transient blocks retained for reuse.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if allocation accounting cannot be read.
    pub fn allocated_transient_allocation_bytes(&self) -> Result<usize, BackendError> {
        self.inner.allocated_transient_allocation_bytes()
    }

    fn reject_grid_sync_without_native_lowering(
        &self,
        program: &Program,
    ) -> Result<(), BackendError> {
        if vyre_driver::grid_sync::contains_grid_sync(program) && !self.supports_grid_sync() {
            return Err(BackendError::UnsupportedFeature {
                name: "cuda_native_grid_sync_lowering (MemoryOrdering::GridSync requires explicit split routing or native cooperative-grid barrier lowering)"
                    .to_string(),
                backend: CUDA_BACKEND_ID.to_string(),
            });
        }
        Ok(())
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
        // Reject programs that ask for capabilities the live CUDA
        // backend doesn't expose BEFORE we attempt PTX emit. Without
        // this gate, indirect_dispatch / f16 / bf16 IR falls all the
        // way down to vyre-emit-ptx and returns a generic
        // "unsupported KernelOp kind" message that doesn't surface
        // the missing-capability contract the dispatch layer is
        // supposed to enforce.
        let required = vyre_foundation::program_caps::scan(program);
        vyre_foundation::program_caps::check_backend_capabilities(
            CUDA_BACKEND_ID,
            self.supports_subgroup_ops(),
            self.supports_f16(),
            self.supports_bf16(),
            self.supports_indirect_dispatch(),
            true,
            self.max_workgroup_size(),
            &required,
        )
        .map_err(|error| BackendError::InvalidProgram {
            fix: error.to_string(),
        })?;
        self.reject_grid_sync_without_native_lowering(program)?;
        self.inner.dispatch(program, inputs, config)
    }

    fn dispatch_async(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Box<dyn vyre_driver::PendingDispatch>, BackendError> {
        self.reject_grid_sync_without_native_lowering(program)?;
        self.inner.dispatch_async(program, inputs, config)
    }

    fn dispatch_borrowed_async(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Box<dyn vyre_driver::PendingDispatch>, BackendError> {
        self.reject_grid_sync_without_native_lowering(program)?;
        self.inner.dispatch_borrowed_async(program, inputs, config)
    }

    fn dispatch_borrowed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        self.reject_grid_sync_without_native_lowering(program)?;
        self.inner
            .dispatch_borrowed_async(program, inputs, config)?
            .await_result()
    }

    fn dispatch_borrowed_into(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
        outputs: &mut vyre_driver::OutputBuffers,
    ) -> Result<(), BackendError> {
        self.reject_grid_sync_without_native_lowering(program)?;
        self.inner
            .dispatch_borrowed_async(program, inputs, config)?
            .await_result_into(outputs)
    }

    fn dispatch_borrowed_timed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<vyre_driver::TimedDispatchResult, BackendError> {
        self.reject_grid_sync_without_native_lowering(program)?;
        self.inner.dispatch_borrowed_timed(program, inputs, config)
    }

    fn allocate_resident(&self, byte_len: usize) -> Result<Resource, BackendError> {
        self.inner
            .allocate_resident(byte_len)
            .map(|handle| Resource::Resident(handle.id))
    }

    fn allocate_device_buffer(
        &self,
        byte_len: usize,
    ) -> Result<Box<dyn vyre_driver::DeviceBuffer>, BackendError> {
        let handle = self.inner.allocate_resident(byte_len)?;
        Ok(Box::new(CudaDeviceBuffer {
            backend_id: CUDA_BACKEND_ID,
            handle,
        }))
    }

    fn upload_device_buffer(
        &self,
        buffer: &mut dyn vyre_driver::DeviceBuffer,
        bytes: &[u8],
    ) -> Result<(), BackendError> {
        let backend_id = buffer.backend_id().to_string();
        let handle = buffer
            .as_any_mut()
            .downcast_mut::<CudaDeviceBuffer>()
            .map(|cuda_buf| cuda_buf.handle)
            .ok_or_else(|| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: upload_device_buffer expected a CudaDeviceBuffer (allocated by `cuda` backend) but got buffer owned by `{backend_id}`."
                ),
            })?;
        self.inner.upload_resident(handle, bytes)
    }

    fn download_device_buffer(
        &self,
        buffer: &dyn vyre_driver::DeviceBuffer,
    ) -> Result<Vec<u8>, BackendError> {
        let cuda_buf = buffer
            .as_any()
            .downcast_ref::<CudaDeviceBuffer>()
            .ok_or_else(|| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: download_device_buffer expected a CudaDeviceBuffer (allocated by `cuda` backend) but got buffer owned by `{}`.",
                    buffer.backend_id()
                ),
            })?;
        self.inner.download_resident(cuda_buf.handle)
    }

    fn free_device_buffer(
        &self,
        buffer: Box<dyn vyre_driver::DeviceBuffer>,
    ) -> Result<(), BackendError> {
        let backend_id = buffer.backend_id().to_string();
        let handle = buffer
            .as_any()
            .downcast_ref::<CudaDeviceBuffer>()
            .map(|cuda_buf| cuda_buf.handle)
            .ok_or_else(|| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: free_device_buffer expected a CudaDeviceBuffer but got buffer owned by `{backend_id}`."
                ),
            })?;
        // Drop the Box (releases the wrapper allocation) before freeing
        // the underlying CUDA-resident allocation. CudaResidentBuffer is
        // Copy so we already captured the handle.
        drop(buffer);
        self.inner.free_resident(handle)
    }

    fn dispatch_with_device_buffers(
        &self,
        program: &Program,
        inputs: &[&dyn vyre_driver::DeviceBuffer],
        outputs: &mut [&mut dyn vyre_driver::DeviceBuffer],
        config: &DispatchConfig,
    ) -> Result<(), BackendError> {
        // Convert &[&dyn DeviceBuffer] into &[Resource::Resident(id)]
        // so we can re-use the existing dispatch_resident_timed path.
        // Outputs are bound by Resource::Resident as well — the kernel
        // writes results in-place into the device-resident buffers; the
        // caller reads them via download_device_buffer afterwards.
        vyre_driver::validate_buffer_ownership(self.id(), inputs.iter().copied())?;
        vyre_driver::validate_buffer_ownership(
            self.id(),
            outputs
                .iter()
                .map(|b| &**b as &dyn vyre_driver::DeviceBuffer),
        )?;
        let resource_capacity =
            inputs
                .len()
                .checked_add(outputs.len())
                .ok_or_else(|| BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA borrowed dispatch resource capacity overflowed usize for {} input buffer(s) plus {} output buffer(s); split the dispatch.",
                        inputs.len(),
                        outputs.len()
                    ),
                })?;
        let mut handles = SmallVec::<[CudaResidentBuffer; 8]>::new();
        reserve_smallvec(
            &mut handles,
            resource_capacity,
            "CUDA borrowed dispatch resource handles",
        )?;
        for buffer in inputs {
            let handle = buffer
                .as_any()
                .downcast_ref::<CudaDeviceBuffer>()
                .ok_or_else(|| BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: dispatch_with_device_buffers expected CudaDeviceBuffer inputs but got buffer owned by `{}`.",
                        buffer.backend_id()
                    ),
                })?
                .handle;
            handles.push(handle);
        }
        for buffer in outputs.iter() {
            let backend_id = buffer.backend_id().to_string();
            let handle = buffer
                .as_any()
                .downcast_ref::<CudaDeviceBuffer>()
                .ok_or_else(|| BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: dispatch_with_device_buffers expected CudaDeviceBuffer outputs but got buffer owned by `{backend_id}`."
                    ),
                })?
                .handle;
            handles.push(handle);
        }
        let _timed = self
            .inner
            .dispatch_resident_timed(program, &handles, config)?;
        Ok(())
    }

    fn upload_resident(&self, resource: &Resource, bytes: &[u8]) -> Result<(), BackendError> {
        let handle = self.inner.resident_handle_from_resource(resource)?;
        self.inner.upload_resident(handle, bytes)
    }

    fn upload_resident_many(&self, uploads: &[(&Resource, &[u8])]) -> Result<(), BackendError> {
        let concrete = self.resolve_uploads(uploads)?;
        self.inner.upload_resident_many(&concrete)
    }

    fn upload_resident_at(
        &self,
        resource: &Resource,
        dst_offset_bytes: usize,
        bytes: &[u8],
    ) -> Result<(), BackendError> {
        let handle = self.inner.resident_handle_from_resource(resource)?;
        self.inner
            .upload_resident_at(handle, dst_offset_bytes, bytes)
    }

    fn upload_resident_at_many(
        &self,
        uploads: &[(&Resource, usize, &[u8])],
    ) -> Result<(), BackendError> {
        let concrete = self.resolve_offset_uploads(uploads)?;
        self.inner.upload_resident_at_many(&concrete)
    }

    fn download_resident(&self, resource: &Resource) -> Result<Vec<u8>, BackendError> {
        let handle = self.inner.resident_handle_from_resource(resource)?;
        self.inner.download_resident(handle)
    }

    fn download_resident_into(
        &self,
        resource: &Resource,
        out: &mut Vec<u8>,
    ) -> Result<(), BackendError> {
        let handle = self.inner.resident_handle_from_resource(resource)?;
        self.inner.download_resident_into(handle, out)
    }

    fn download_resident_range(
        &self,
        resource: &Resource,
        byte_offset: usize,
        byte_len: usize,
    ) -> Result<Vec<u8>, BackendError> {
        let handle = self.inner.resident_handle_from_resource(resource)?;
        self.inner
            .download_resident_range(handle, byte_offset, byte_len)
    }

    fn download_resident_range_into(
        &self,
        resource: &Resource,
        byte_offset: usize,
        byte_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), BackendError> {
        let handle = self.inner.resident_handle_from_resource(resource)?;
        self.inner
            .download_resident_range_into(handle, byte_offset, byte_len, out)
    }

    fn download_resident_ranges_into(
        &self,
        ranges: &[(&Resource, usize, usize)],
        outputs: &mut [&mut Vec<u8>],
    ) -> Result<(), BackendError> {
        let concrete = self.resolve_download_ranges(ranges)?;
        self.inner.download_resident_ranges_into(&concrete, outputs)
    }

    fn free_resident(&self, resource: Resource) -> Result<(), BackendError> {
        let handle = self.inner.resident_handle_from_resource(&resource)?;
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

    fn dispatch_resident_sequence_read_ranges_into(
        &self,
        steps: &[vyre_driver::backend::ResidentDispatchStep<'_>],
        read_ranges: &[vyre_driver::backend::ResidentReadRange<'_>],
        outputs: &mut [&mut Vec<u8>],
    ) -> Result<(), BackendError> {
        if read_ranges.len() != outputs.len() {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident sequence ranged readback expected matching range/output counts but got {} range(s) and {} output(s).",
                    read_ranges.len(),
                    outputs.len()
                ),
            });
        }
        let mut handle_sets =
            SmallVec::<[SmallVec<[crate::backend::CudaResidentBuffer; 8]>; 8]>::new();
        reserve_smallvec(
            &mut handle_sets,
            steps.len(),
            "CUDA resident sequence handle sets",
        )?;
        for step in steps {
            handle_sets.push(self.inner.resident_handles_from_resources(step.resources)?);
        }
        let mut concrete_steps =
            SmallVec::<[crate::backend::CudaResidentDispatchStep<'_>; 8]>::new();
        reserve_smallvec(
            &mut concrete_steps,
            steps.len(),
            "CUDA resident sequence steps",
        )?;
        for (step, handles) in steps.iter().zip(handle_sets.iter()) {
            let mut config = DispatchConfig::default();
            config.grid_override = step.grid_override;
            concrete_steps.push(crate::backend::CudaResidentDispatchStep {
                program: step.program,
                handles,
                config,
            });
        }

        let (read_handles, concrete_readbacks) = self.resolve_read_ranges(read_ranges)?;

        let uploads: [(crate::backend::CudaResidentBuffer, &[u8]); 0] = [];
        self.inner
            .upload_resident_many_sequence_read_ranges_borrowed_into(
                &uploads,
                &concrete_steps,
                &read_handles,
                &concrete_readbacks,
                outputs,
            )
    }

    fn dispatch_resident_repeated_sequence_read_ranges_into(
        &self,
        prefix_steps: &[vyre_driver::backend::ResidentDispatchStep<'_>],
        repeated_steps: &[vyre_driver::backend::ResidentDispatchStep<'_>],
        repeat_count: u32,
        read_ranges: &[vyre_driver::backend::ResidentReadRange<'_>],
        outputs: &mut [&mut Vec<u8>],
    ) -> Result<(), BackendError> {
        let repeat_count =
            usize::try_from(repeat_count).map_err(|error| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA repeated resident sequence count does not fit usize: {error}."
                ),
            })?;
        if read_ranges.len() != outputs.len() {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA repeated resident sequence ranged readback expected matching range/output counts but got {} range(s) and {} output(s).",
                    read_ranges.len(),
                    outputs.len()
                ),
            });
        }

        let mut prefix_handle_sets =
            SmallVec::<[SmallVec<[crate::backend::CudaResidentBuffer; 8]>; 8]>::new();
        reserve_smallvec(
            &mut prefix_handle_sets,
            prefix_steps.len(),
            "CUDA repeated resident prefix handle sets",
        )?;
        for step in prefix_steps {
            prefix_handle_sets.push(self.inner.resident_handles_from_resources(step.resources)?);
        }
        let mut repeated_handle_sets =
            SmallVec::<[SmallVec<[crate::backend::CudaResidentBuffer; 8]>; 8]>::new();
        let repeated_handle_capacity = if repeat_count == 0 {
            0
        } else {
            repeated_steps.len()
        };
        reserve_smallvec(
            &mut repeated_handle_sets,
            repeated_handle_capacity,
            "CUDA repeated resident repeated handle sets",
        )?;
        if repeat_count != 0 {
            for step in repeated_steps {
                repeated_handle_sets
                    .push(self.inner.resident_handles_from_resources(step.resources)?);
            }
        }
        let mut concrete_prefix =
            SmallVec::<[crate::backend::CudaResidentDispatchStep<'_>; 8]>::new();
        reserve_smallvec(
            &mut concrete_prefix,
            prefix_steps.len(),
            "CUDA repeated resident prefix steps",
        )?;
        for (step, handles) in prefix_steps.iter().zip(prefix_handle_sets.iter()) {
            let mut config = DispatchConfig::default();
            config.grid_override = step.grid_override;
            concrete_prefix.push(crate::backend::CudaResidentDispatchStep {
                program: step.program,
                handles,
                config,
            });
        }
        let mut concrete_repeated =
            SmallVec::<[crate::backend::CudaResidentDispatchStep<'_>; 8]>::new();
        reserve_smallvec(
            &mut concrete_repeated,
            repeated_handle_sets.len(),
            "CUDA repeated resident repeated steps",
        )?;
        if repeat_count != 0 {
            for (step, handles) in repeated_steps.iter().zip(repeated_handle_sets.iter()) {
                let mut config = DispatchConfig::default();
                config.grid_override = step.grid_override;
                concrete_repeated.push(crate::backend::CudaResidentDispatchStep {
                    program: step.program,
                    handles,
                    config,
                });
            }
        }

        let (read_handles, concrete_readbacks) = self.resolve_read_ranges(read_ranges)?;
        let uploads: [(crate::backend::CudaResidentBuffer, &[u8]); 0] = [];
        self.inner
            .upload_resident_many_repeated_sequence_read_ranges_borrowed_into(
                &uploads,
                &concrete_prefix,
                &concrete_repeated,
                repeat_count,
                &read_handles,
                &concrete_readbacks,
                outputs,
            )
    }

    fn compile_native(
        &self,
        program: &Program,
        config: &DispatchConfig,
    ) -> Result<Option<Arc<dyn vyre_driver::CompiledPipeline>>, BackendError> {
        self.reject_grid_sync_without_native_lowering(program)?;
        self.inner.compile_native(program, config).map(Some)
    }

    fn compile_native_shared(
        &self,
        program: Arc<Program>,
        config: &DispatchConfig,
    ) -> Result<Option<Arc<dyn vyre_driver::CompiledPipeline>>, BackendError> {
        self.reject_grid_sync_without_native_lowering(program.as_ref())?;
        self.inner.compile_native_shared(program, config).map(Some)
    }

    fn pipeline_cache_snapshot(&self) -> Option<vyre_driver::pipeline::PipelineCacheSnapshot> {
        Some(self.inner.pipeline_cache_snapshot())
    }

    fn backend_metric_snapshot(&self) -> Vec<(&'static str, u64)> {
        let source_cache = self.inner.ptx_source_cache_snapshot();
        let mut metrics = Vec::new();
        match u64::try_from(source_cache.entries) {
            Ok(entries) => metrics.push(("cuda_ptx_source_cache_entries", entries)),
            Err(source) => {
                tracing::error!(
                    "CUDA PTX source cache entry count cannot fit u64: {source}. Fix: shard backend metrics before source-cache cardinality exceeds u64."
                );
                metrics.push(("cuda_ptx_source_cache_entries_unrepresentable", 1));
            }
        }
        metrics.push(("cuda_ptx_source_cache_hits", source_cache.hits));
        metrics.push(("cuda_ptx_source_cache_misses", source_cache.misses));
        metrics
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

    fn allows_host_grid_sync_split(&self) -> bool {
        false
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

#[cfg(test)]
mod tests {
    #[test]
    fn public_cuda_resident_helpers_reserve_smallvecs_fallibly() {
        let source = include_str!("lib.rs");
        assert!(
            source.contains("use crate::backend::staging_reserve::reserve_smallvec;"),
            "Fix: public CUDA resident helpers must use the shared fallible staging reservation contract."
        );
        assert!(
            !source.contains(concat!(
                "SmallVec::<",
                "[(CudaResidentBuffer, &'a [u8]); 8]>::with_capacity"
            )) && !source.contains(concat!(
                "SmallVec::<",
                "[(CudaResidentBuffer, usize, &'a [u8]); 8]>::with_capacity"
            )) && !source.contains(concat!(
                "SmallVec::<",
                "[(CudaResidentBuffer, usize, usize); 8]>::with_capacity"
            )) && !source.contains(concat!(
                "SmallVec::<",
                "[CudaResidentBuffer; 8]>::with_capacity"
            )) && !source.contains(concat!(
                "SmallVec::<",
                "[SmallVec<[crate::backend::CudaResidentBuffer; 8]>; 8]>::with_capacity"
            )) && !source.contains(concat!(
                "SmallVec::<",
                "[crate::backend::CudaResidentDispatchStep<'_>; 8]>::with_capacity"
            )),
            "Fix: public CUDA resident helpers must reserve fallibly instead of using infallible SmallVec capacity growth."
        );
        assert!(
            source.contains("CUDA resident sequence handle sets")
                && source.contains("CUDA repeated resident repeated steps")
                && source.contains("CUDA borrowed dispatch resource handles"),
            "Fix: public CUDA resident sequence and borrowed-buffer staging paths must expose specific fallible-reservation labels."
        );
    }
}
