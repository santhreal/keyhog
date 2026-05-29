//! SPIR-V backend for vyre.
//!
//! Reuses the shared naga::Module builder family and emits
//! SPIR-V rather than WGSL. Intended for consumers targeting Vulkan-compatible
//! compute pipelines (Vulkan 1.0+, Android NDK compute, desktop Vulkan).
//!
//! ```no_run
//! use vyre_driver_spirv::SpirvBackend;
//! // let module: naga::Module = ...;   // built via shared vyre naga emit
//! // let words: Vec<u32> = SpirvBackend::emit_spv(&module).unwrap();
//! ```
//!
//! The crate registers a `BackendRegistration` named `"spirv"` via inventory
//! so `vyre::registered_backends()` enumerates it alongside other
//! `photonic`.

// Vulkan driver bindings (`ash::vk::*`) are inherently unsafe FFI;
// every call site is the boundary between safe vyre code and the Vulkan
// driver API. Allow `unsafe` here so the rest of the workspace can keep
// `unsafe_code = "deny"` while this backend wraps ash properly with
// per-call Safety: comments.
#![allow(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(missing_docs)]

/// SPIR-V backend implementation. Contains `SpirvBackend` and the
/// naga::back::spv glue that turns a `vyre::Program` into SPIR-V
/// bytes.
/// SpirV element.
/// SpirV element.
pub mod backend;
/// Vulkan compute dispatch implementation.
mod vulkan;
/// The SPIR-V `VyreBackend` implementation.
/// SpirV element.
/// SpirV element.
pub use backend::SpirvBackend;

use std::sync::Arc;

use vyre_driver::{BackendError, BackendRegistration, DispatchConfig, VyreBackend};
use vyre_foundation::ir::Program;

/// Stable backend identifier for conform certificates.
pub const SPIRV_BACKEND_ID: &str = "spirv";

/// Live Vulkan-backed SPIR-V backend.
///
/// Acquires a Vulkan device on construction and uses it to dispatch
/// SPIR-V compute pipelines at runtime. If no Vulkan device is available,
/// acquisition returns a structured error.
#[derive(Debug, Clone)]
pub struct SpirvBackendRegistration {
    device: Arc<vulkan::VulkanDevice>,
}

impl SpirvBackendRegistration {
    /// Acquire a new SPIR-V backend by probing for a Vulkan compute device.
    ///
    /// # Errors
    /// Returns [`BackendError`] when no Vulkan loader or compatible GPU is found.
    pub fn acquire() -> Result<Self, BackendError> {
        let device = vulkan::VulkanDevice::acquire()?;
        Ok(Self {
            device: Arc::new(device),
        })
    }
}

impl vyre_driver::backend::private::Sealed for SpirvBackendRegistration {}

fn spirv_device_buffer_unsupported() -> BackendError {
    BackendError::UnsupportedFeature {
        name: format!(
            "{} requires native Vulkan-resident buffers; HostShimBuffer dispatch is forbidden",
            vyre_driver::DEVICE_BUFFER_FEATURE
        ),
        backend: SPIRV_BACKEND_ID.to_string(),
    }
}

impl VyreBackend for SpirvBackendRegistration {
    fn id(&self) -> &'static str {
        SPIRV_BACKEND_ID
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
        let borrowed: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
        self.dispatch_borrowed(program, &borrowed, config)
    }

    fn dispatch_borrowed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let spv_words = SpirvBackend::program_to_spv(program).map_err(|e| {
            BackendError::KernelCompileFailed {
                backend: SPIRV_BACKEND_ID.to_string(),
                compiler_message: format!("{e}. Fix: validate the Program IR before dispatch."),
            }
        })?;

        // SAFETY: FFI to ash::vk. Handle lifetimes are documented at the
        // surrounding VulkanDevice construction site; the Drop impl owns
        // destruction.
        unsafe { vulkan::dispatch_program(&self.device, program, &spv_words, inputs, config) }
    }

    fn allocate_device_buffer(
        &self,
        byte_len: usize,
    ) -> Result<Box<dyn vyre_driver::DeviceBuffer>, BackendError> {
        let _ = byte_len;
        Err(spirv_device_buffer_unsupported())
    }

    fn upload_device_buffer(
        &self,
        buffer: &mut dyn vyre_driver::DeviceBuffer,
        bytes: &[u8],
    ) -> Result<(), BackendError> {
        let _ = (buffer, bytes);
        Err(spirv_device_buffer_unsupported())
    }

    fn download_device_buffer(
        &self,
        buffer: &dyn vyre_driver::DeviceBuffer,
    ) -> Result<Vec<u8>, BackendError> {
        let _ = buffer;
        Err(spirv_device_buffer_unsupported())
    }

    fn free_device_buffer(
        &self,
        buffer: Box<dyn vyre_driver::DeviceBuffer>,
    ) -> Result<(), BackendError> {
        drop(buffer);
        Err(spirv_device_buffer_unsupported())
    }

    fn dispatch_with_device_buffers(
        &self,
        program: &Program,
        inputs: &[&dyn vyre_driver::DeviceBuffer],
        outputs: &mut [&mut dyn vyre_driver::DeviceBuffer],
        config: &DispatchConfig,
    ) -> Result<(), BackendError> {
        vyre_driver::default_dispatch_with_device_buffers(self, program, inputs, outputs, config)
    }

    fn max_workgroup_size(&self) -> [u32; 3] {
        let max = self.device.properties.limits.max_compute_work_group_size;
        [max[0], max[1], max[2]]
    }

    fn max_compute_workgroups_per_dimension(&self) -> u32 {
        let max = self.device.properties.limits.max_compute_work_group_count;
        max[0]
    }

    fn max_compute_invocations_per_workgroup(&self) -> u32 {
        self.device
            .properties
            .limits
            .max_compute_work_group_invocations
    }

    fn max_storage_buffer_bytes(&self) -> u64 {
        self.device.properties.limits.max_storage_buffer_range as u64
    }

    fn supports_grid_sync(&self) -> bool {
        false
    }

    fn supports_subgroup_ops(&self) -> bool {
        false
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
        false
    }

    fn device_profile(&self) -> vyre_driver::DeviceProfile {
        let max_workgroup_size = self.max_workgroup_size();
        vyre_driver::DeviceProfile {
            backend: self.id(),
            supports_subgroup_ops: false,
            supports_indirect_dispatch: false,
            supports_distributed_collectives: false,
            supports_specialization_constants: false,
            supports_f16: false,
            supports_bf16: false,
            supports_trap_propagation: false,
            supports_tensor_cores: false,
            has_mul_high: false,
            has_dual_issue_fp32_int32: false,
            has_subgroup_shuffle: false,
            has_shared_memory: false,
            max_native_int_width: 32,
            max_workgroup_size,
            max_invocations_per_workgroup: self.max_compute_invocations_per_workgroup(),
            max_shared_memory_bytes: self.device.properties.limits.max_compute_shared_memory_size,
            max_storage_buffer_binding_size: self.max_storage_buffer_bytes(),
            subgroup_size: 0,
            compute_units: 0,
            regs_per_thread_max: 0,
            l1_cache_bytes: 0,
            l2_cache_bytes: 0,
            mem_bw_gbps: 0,
            ideal_unroll_depth: 0,
            ideal_vector_pack_bits: 0,
            ideal_workgroup_tile: [0, 0, 0],
            shared_memory_bank_count: 0,
            shared_memory_bank_width_bytes: 0,
        }
    }
}

/// Factory for the inventory registration path.
pub fn spirv_factory() -> Result<Box<dyn VyreBackend>, BackendError> {
    SpirvBackendRegistration::acquire().map(|backend| Box::new(backend) as Box<dyn VyreBackend>)
}

/// Op-support set  -  SPIR-V through naga supports every op the naga::Module
/// builders already emit. Empty at the registration layer; the conform runner
/// populates real coverage at runtime.
pub fn spirv_supported_ops() -> &'static std::collections::HashSet<vyre_foundation::ir::OpId> {
    use std::sync::OnceLock;
    static OPS: OnceLock<std::collections::HashSet<vyre_foundation::ir::OpId>> = OnceLock::new();
    OPS.get_or_init(std::collections::HashSet::new)
}

inventory::submit! {
    BackendRegistration {
        id: SPIRV_BACKEND_ID,
        factory: spirv_factory,
        supported_ops: spirv_supported_ops,
    }
}

// V7-EXT-021: declare router precedence inline. SPIR-V is rank 30.
inventory::submit! {
    vyre_driver::backend::BackendPrecedence {
        id: SPIRV_BACKEND_ID,
        rank: 30,
    }
}

inventory::submit! {
    vyre_driver::backend::BackendCapability {
        id: SPIRV_BACKEND_ID,
        dispatches: true,
    }
}
