//! SPIR-V backend for vyre.
//!
//! Reuses the shared naga::Module builder family with vyre-wgpu and emits
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
//! so `vyre::registered_backends()` enumerates it alongside `wgpu` and
//! `photonic`.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(missing_docs)]

/// SPIR-V backend implementation. Contains `SpirvBackend` and the
/// naga::back::spv glue that turns a `vyre::Program` into SPIR-V
/// bytes.
/// SpirV element.
/// SpirV element.
pub mod backend;
/// The SPIR-V `VyreBackend` implementation.
/// SpirV element.
/// SpirV element.
pub use backend::SpirvBackend;

use vyre_driver::{BackendError, BackendRegistration, DispatchConfig, VyreBackend};
use vyre_foundation::ir::Program;

/// Stable backend identifier for conform certificates.
pub const SPIRV_BACKEND_ID: &str = "spirv";

/// Wrapper implementing `VyreBackend`.
///
/// SPIR-V dispatch requires a Vulkan driver which this crate deliberately
/// does not vendor; the registered backend emits SPIR-V via
/// [`SpirvBackend::emit_spv`] and expects the caller to own the Vulkan
/// dispatch stack. The trait's `dispatch` method returns a structured
/// refusal pointing the caller at the intended flow.
#[derive(Debug, Default, Clone, Copy)]
pub struct SpirvBackendRegistration;

impl vyre_driver::backend::private::Sealed for SpirvBackendRegistration {}

impl VyreBackend for SpirvBackendRegistration {
    fn id(&self) -> &'static str {
        SPIRV_BACKEND_ID
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn dispatch(
        &self,
        _program: &Program,
        _inputs: &[Vec<u8>],
        _config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        Err(BackendError::new(
            "Fix: vyre-spirv emits SPIR-V words via SpirvBackend::emit_spv; \
             run the returned blob on your Vulkan dispatch stack. The registered \
             backend surface does not own a Vulkan device.",
        ))
    }
}

/// Factory for the inventory registration path.
pub fn spirv_factory() -> Result<Box<dyn VyreBackend>, BackendError> {
    Ok(Box::new(SpirvBackendRegistration))
}

/// Op-support set — SPIR-V through naga supports every op the naga::Module
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

// V7-EXT-021: declare router precedence inline. SPIR-V is rank 20 —
// higher priority than the WGSL path (rank 30) when both are linked.
inventory::submit! {
    vyre_driver::backend::BackendPrecedence {
        id: SPIRV_BACKEND_ID,
        rank: 20,
    }
}
