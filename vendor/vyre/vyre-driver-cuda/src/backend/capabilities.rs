//! CUDA capability, feature-flag, and validation policy.

use vyre_driver::validation::{LaunchGeometryLimits, ProgramValidationCaps};
use vyre_driver::{BackendError, DispatchConfig};
use vyre_foundation::ir::Program;
use vyre_foundation::validate::ValidationOptions;
use std::sync::Arc;

use super::dispatch::CudaBackend;

impl CudaBackend {
    /// Compute capability as (major, minor).
    #[must_use]
    pub fn compute_capability(&self) -> (u32, u32) {
        self.caps.compute_capability
    }

    /// CUDA SM target number used by PTX emission.
    #[must_use]
    pub fn target_sm(&self) -> u32 {
        self.caps.native_sm()
    }

    /// CUDA SM target used by the current PTX ISA emitter.
    #[must_use]
    pub fn ptx_target_sm(&self) -> u32 {
        self.ptx_target_sm
    }

    /// Total device memory in bytes.
    #[must_use]
    pub fn device_memory_bytes(&self) -> u64 {
        self.caps.total_memory
    }

    /// Maximum number of threads per CUDA block.
    #[must_use]
    pub fn max_threads_per_block(&self) -> u32 {
        self.caps.max_threads_per_block_u32()
    }

    /// Maximum CUDA block dimensions.
    #[must_use]
    pub fn max_block_dim(&self) -> [u32; 3] {
        self.caps.max_block_dim_u32()
    }

    /// Maximum CUDA grid dimensions.
    #[must_use]
    pub fn max_grid_dim(&self) -> [u32; 3] {
        self.caps.max_grid_dim_u32()
    }

    /// Shared memory available per CUDA thread block in bytes.
    #[must_use]
    pub fn max_shared_memory_per_block_bytes(&self) -> u32 {
        self.caps.shared_memory_per_block_bytes()
    }

    /// CUDA warp size used by subgroup-style execution.
    #[must_use]
    pub fn warp_size(&self) -> Option<u32> {
        self.caps.warp_size_u32()
    }

    /// Whether the device has hardware subgroup/warp execution.
    #[must_use]
    pub fn hardware_supports_subgroup_ops(&self) -> bool {
        self.warp_size()
            .map(vyre_driver::SubgroupCaps::native)
            .is_some_and(|caps| caps.supports_subgroup)
    }

    /// Whether the device can execute asynchronous CUDA work concurrently.
    #[must_use]
    pub fn hardware_supports_async_compute(&self) -> bool {
        self.caps.concurrent_kernels || self.caps.async_engine_count > 0
    }

    /// Whether this device can run a cooperative whole-grid barrier.
    #[must_use]
    pub fn hardware_supports_grid_sync(&self) -> bool {
        self.caps.compute_capability >= (6, 0) && self.caps.cooperative_launch
    }

    /// Whether the device generation has native fp16 arithmetic support.
    #[must_use]
    pub fn hardware_supports_f16(&self) -> bool {
        self.caps.hardware_supports_f16()
    }

    /// Whether the device generation has native bf16 arithmetic support.
    #[must_use]
    pub fn hardware_supports_bf16(&self) -> bool {
        self.caps.hardware_supports_bf16()
    }

    /// Whether the device generation has NVIDIA tensor-core instructions.
    #[must_use]
    pub fn hardware_supports_tensor_cores(&self) -> bool {
        self.caps.hardware_supports_tensor_cores()
    }

    /// Whether this backend launches grid-sync kernels through the cooperative ABI.
    #[must_use]
    pub fn lowers_grid_sync(&self) -> bool {
        false
    }

    /// Whether CUDA can execute `MemoryOrdering::GridSync` inside one dispatch.
    pub fn supports_grid_sync(&self) -> bool {
        self.hardware_supports_grid_sync() && self.lowers_grid_sync()
    }

    /// Whether CUDA PTX lowering emits tensor-core instructions.
    #[must_use]
    pub fn lowers_tensor_core_ops(&self) -> bool {
        true
    }

    /// Pipeline feature flags that participate in shared cache identity.
    #[must_use]
    pub fn pipeline_feature_flags(&self) -> vyre_driver::pipeline::PipelineFeatureFlags {
        let mut flags = vyre_driver::pipeline::PipelineFeatureFlags::empty();
        if self.hardware_supports_subgroup_ops() {
            flags = flags.union(vyre_driver::pipeline::PipelineFeatureFlags::SUBGROUP_OPS);
        }
        if self.hardware_supports_f16() {
            flags = flags.union(vyre_driver::pipeline::PipelineFeatureFlags::F16);
        }
        if self.hardware_supports_bf16() {
            flags = flags.union(vyre_driver::pipeline::PipelineFeatureFlags::BF16);
        }
        if self.hardware_supports_tensor_cores() && self.lowers_tensor_core_ops() {
            flags = flags.union(vyre_driver::pipeline::PipelineFeatureFlags::TENSOR_CORES);
        }
        if self.hardware_supports_async_compute() {
            flags = flags.union(vyre_driver::pipeline::PipelineFeatureFlags::ASYNC_COMPUTE);
        }
        flags
    }

    pub(crate) fn ptx_for_program(
        &self,
        program: &Program,
        config: &DispatchConfig,
    ) -> Result<String, BackendError> {
        self.ptx_for_program_cached(program, config)
            .map(|source| source.as_ref().to_string())
    }

    pub(crate) fn ptx_for_program_cached(
        &self,
        program: &Program,
        config: &DispatchConfig,
    ) -> Result<Arc<str>, BackendError> {
        let subgroup_size = self.warp_size().ok_or_else(|| BackendError::InvalidProgram {
            fix: "Fix: CUDA device probe reported no hardware warp size on a GPU-required host; fix the CUDA capability probe before lowering."
                .to_string(),
        })?;
        let key = self.ptx_source_cache.key_for_program(
            program,
            config,
            self.ptx_target_sm(),
            subgroup_size,
            self.pipeline_feature_flags(),
        );
        self.ptx_source_cache.get_or_lower(key, || {
            crate::codegen::program_to_ptx_for_sm_and_subgroup(
                program,
                config,
                self.ptx_target_sm(),
                subgroup_size,
            )
            .map_err(|compiler_message| BackendError::KernelCompileFailed {
                backend: crate::CUDA_BACKEND_ID.to_string(),
                compiler_message,
            })
        })
    }

    pub(crate) fn launch_limits(&self) -> LaunchGeometryLimits {
        LaunchGeometryLimits {
            backend: "CUDA",
            max_threads_per_block: self.max_threads_per_block(),
            max_block_dim: self.max_block_dim(),
            max_grid_dim: self.max_grid_dim(),
        }
    }

    pub(crate) fn program_validation_caps(&self) -> ProgramValidationCaps {
        ProgramValidationCaps {
            backend_id: crate::CUDA_BACKEND_ID,
            supports_subgroup_ops: self.hardware_supports_subgroup_ops(),
            supports_f16: self.hardware_supports_f16(),
            supports_bf16: self.hardware_supports_bf16(),
            supports_indirect_dispatch: false,
            supports_trap_propagation: true,
            max_workgroup_size: self.max_block_dim(),
        }
    }

    pub(crate) fn validation_options(&self) -> ValidationOptions<'_> {
        ValidationOptions::default()
            .with_backend_capabilities(self.caps.to_device_profile().validation_capabilities())
            .with_shadowing(true)
    }

    pub(crate) fn validate_program_cached(&self, program: &Program) -> Result<(), BackendError> {
        if std::env::var_os("VYRE_CUDA_VALIDATE_DISPATCH").is_none() {
            return Ok(());
        }
        self.validation_cache.get_or_validate(
            program,
            self.validation_options(),
            crate::cuda_supported_ops(),
            self.program_validation_caps(),
        )
    }
}
