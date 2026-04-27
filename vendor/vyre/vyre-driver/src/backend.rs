//! Frozen backend extension contract.
//!
//! Vyre treats GPU compute as a target-agnostic intermediate representation.
//! This module defines the narrow interface that every backend — WGSL, Metal,
//! CUDA, or the pure-Rust reference interpreter — must implement. Frontends
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
mod error;
mod pending_dispatch;
mod vyre_backend;

pub use capability::{Backend, Executable, Memory, MemoryRef, Streamable};
pub use dialect_supported_ops::{dialect_and_language_supported_ops, dialect_only_supported_ops};
pub use registry::{
    backend_dispatches, backend_precedence, core_supported_ops, registered_backends,
    registered_backends_by_precedence, registered_backends_by_precedence_slice, BackendCapability,
    BackendPrecedence, BackendRegistration,
};
pub use validation::{default_supported_ops, node_op_id, validate_program};

pub use compiled_pipeline::CompiledPipeline;
pub use error::{BackendError, ErrorCode};
pub use pending_dispatch::PendingDispatch;
pub use vyre_backend::{DispatchConfig, Resource, VyreBackend};

#[doc(hidden)]
pub mod private {
    pub trait Sealed {}
}
