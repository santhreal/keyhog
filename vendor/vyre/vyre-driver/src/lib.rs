#![allow(unused_imports)]
#![allow(
    clippy::only_used_in_recursion,
    clippy::result_unit_err,
    clippy::module_inception
)]
//! vyre-driver — substrate-agnostic backend machinery.
//!
//! Registry, runtime, pipeline, routing, diagnostics, and the VyreBackend
//! trait. Backend-specific crates (vyre-driver-wgpu, vyre-driver-spirv)
//! depend on this crate and contribute lowerings via the inventory
//! collection mechanism.

#![allow(missing_docs)]

/// VyreBackend trait, BackendError, capability records, validation.
pub mod backend;
/// Structured, machine-readable diagnostic rendering.
pub mod diagnostics;
/// Compiled-pipeline cache, dispatch config, batched dispatch.
pub mod pipeline;
/// Dialect registry, OpDef registration, lowering tables, and interner.
pub mod registry;
/// Runtime routing: profile-guided variant selection, algorithm heuristics.
pub mod routing;
/// Sampled CPU-reference shadow execution of live dispatches.
pub mod shadow;

/// G6: speculative rule evaluation with commit/rollback. Runs the
/// expensive confirmer on every tile, commits only tiles whose
/// pre-filter passed. Hides gather latency + improves subgroup
/// uniformity. Scaffold.
pub mod speculate;

/// G7: persistent-thread engine + device-side work queue.
/// Eliminates per-file kernel-launch overhead for streams of
/// many small scan jobs. Scaffold (raw-Vulkan path gated behind
/// the `persistent` feature).
pub mod persistent;
/// Re-exports the unified vyre error type from `vyre-foundation`.
pub use vyre_foundation::error;

pub use backend::{
    BackendError, BackendRegistration, CompiledPipeline, DispatchConfig, Executable, Memory,
    MemoryRef, PendingDispatch, Resource, VyreBackend,
};
pub use diagnostics::{Diagnostic, DiagnosticCode, OpLocation, Severity};
pub use error::Error;
pub use pipeline::{
    compile, compile_shared, PipelineCacheKey, PipelineFeatureFlags,
    CURRENT_PIPELINE_CACHE_KEY_VERSION,
};
pub use registry::{
    default_validator, intern_string, AttrSchema, AttrType, Category, Chain, Dialect,
    DialectRegistration, DialectRegistry, DuplicateOpIdError, EnforceGate, EnforceVerdict,
    InternedOpId, LoweringCtx, LoweringTable, MetalBuilder, MetalModule, MutationClass,
    NagaBuilder, OpBackendTarget, OpDef, OpDefRegistration, PtxBuilder, PtxModule, ReferenceKind,
    Signature, SpirvBuilder, Target, TypedParam,
};
pub use routing::{select_sort_backend, Distribution, RoutingTable, SortBackend};
