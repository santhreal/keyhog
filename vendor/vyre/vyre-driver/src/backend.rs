//! Frozen backend extension contract.
//!
//! Vyre treats GPU compute as a target-agnostic intermediate representation.
//! This module defines the narrow interface that every backend or the
//! pure-Rust reference interpreter must implement. Frontends
//! emit `Program` values without knowing which backend will execute them, and
//! backends compete on implementation quality without negotiating API changes.
//! The trait signature is frozen under the five-year stability contract from
//! `ARCHITECTURE.md`.

mod capability;
mod dialect_supported_ops;
pub mod lowering;
mod registry;
pub mod validation;

mod compiled_pipeline;
mod dispatch_config;
mod dispatch_result;
mod error;
mod pending_dispatch;
mod resource;
mod typed_dispatch;
mod vyre_backend;

pub use capability::{Backend, Executable, Memory, MemoryRef, Streamable};
pub use dialect_supported_ops::{dialect_and_language_supported_ops, dialect_only_supported_ops};
pub use registry::{
    acquire, acquire_preferred_dispatch_backend, backend_dispatches, backend_precedence,
    core_supported_ops, registered_backends, registered_backends_by_precedence,
    registered_backends_by_precedence_slice, BackendCapability, BackendPrecedence,
    BackendRegistration,
};
pub use validation::{
    default_supported_ops, default_supported_ops_with_trap, node_op_id, validate_program,
};
// `validate_program_for_backend` lives at the crate root in
// `crate::validation` (the cross-backend variant), not under the
// per-backend submodule. Re-export it here so legacy call sites that
// reach `vyre_driver::backend::validate_program_for_backend` keep
// resolving against the same path.
pub use crate::validation::validate_program_for_backend;

pub use compiled_pipeline::CompiledPipeline;
pub use dispatch_config::DispatchConfig;
pub use dispatch_result::{OutputBuffers, TimedDispatchResult};
pub use error::{BackendError, ErrorCode};
pub use pending_dispatch::PendingDispatch;
pub use resource::Resource;
pub use typed_dispatch::TypedDispatchExt;
pub use vyre_backend::VyreBackend;

#[doc(hidden)]
pub mod private {
    pub trait Sealed {}
}
