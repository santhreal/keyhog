//! vyre-foundation — substrate-neutral compiler foundation.
//!
//! Defines the vyre IR (`Expr`, `Node`, `Program`), the type system, the
//! memory model, the wire format, visitor traits, and extension resolvers.
//! Every other vyre crate depends on this one; this crate depends only on
//! `vyre-spec`, `vyre-macros`, and lightweight third-party data crates.
//! It never knows about `naga`, `wgpu`, a dialect, or a backend.

#![allow(
    clippy::duplicate_mod,
    clippy::too_many_arguments,
    clippy::double_must_use,
    clippy::module_inception,
    clippy::should_implement_trait,
    clippy::type_complexity,
    // `dead_code` is kept as a crate-level allow while the 0.7 dialect-sweep
    // decides which of the 14 currently-unused pub(crate) items (old matching
    // engine residue, `FLAG_COMPRESSED`/`FLAG_SEALED` wire reservations,
    // `primitive_math_div_cpu` / `cpu_fn_for_composition` CPU refs,
    // `U32_*` buffer-layout constants, validator `call_input_count` helper)
    // are 0.7 hooks vs. genuine cruft. Removing the allow surfaces these
    // warnings; a follow-up pass marks each site with either deletion or a
    // per-item `#[allow(dead_code, reason = "0.7: …")]`.
    dead_code
)]

extern crate self as vyre;

/// Structured optimizer diagnostics surfaced to IDEs and CI annotators.
///
/// Lightweight diagnostic type used by foundation optimizer passes.
///
/// Drivers embed these into their richer diagnostic surface; foundation
/// only needs a human-readable message plus an optional pass/op location
/// so that pass-scheduling errors can be rendered without pulling in
/// driver-tier dependencies.
pub mod diagnostics {

    /// Error-level diagnostic with an optional location hint.
    #[derive(Debug, Clone)]
    pub struct Diagnostic {
        /// Human-readable diagnostic message.
        pub message: String,
        /// Optional op/pass location the diagnostic refers to.
        pub location: Option<OpLocation>,
    }

    impl Diagnostic {
        /// Build an error-level diagnostic with no location.
        #[must_use]
        pub fn error(msg: impl Into<String>) -> Self {
            Self {
                message: msg.into(),
                location: None,
            }
        }

        /// Attach an op/pass location to this diagnostic.
        #[must_use]
        pub fn with_location(mut self, loc: OpLocation) -> Self {
            self.location = Some(loc);
            self
        }
    }

    /// Location handle pointing at a specific pass or op id.
    #[derive(Debug, Clone)]
    pub struct OpLocation {
        /// Stable pass or op identifier.
        pub op_id: String,
    }

    impl OpLocation {
        /// Construct a location hint from an op id.
        #[must_use]
        pub fn op(op_id: impl Into<String>) -> Self {
            Self {
                op_id: op_id.into(),
            }
        }
    }
}

pub mod ir {
    //! The vyre intermediate representation.
    pub use crate::ir_inner::model;
    pub use crate::ir_inner::model::arena::{ArenaProgram, ExprArena, ExprRef};
    pub use crate::ir_inner::model::expr::{Expr, ExprNode, Ident};
    pub use crate::ir_inner::model::node::{Node, NodeExtension};
    pub use crate::ir_inner::model::node_kind::{
        EvalError, InterpCtx, NodeId, NodeStorage, OpId, RegionId, Value, VarId,
    };
    pub use crate::ir_inner::model::program::{
        BufferDecl, CacheLocality, MemoryHints, MemoryKind, Program,
    };
    pub use crate::ir_inner::model::types::{
        AtomicOp, BinOp, BufferAccess, Convention, DataType, OpSignature, UnOp,
    };
    pub use crate::memory_model;
    pub use crate::memory_model::MemoryOrdering;
    pub use crate::serial::text;
    pub use crate::transform::inline::{inline_calls, inline_calls_with_resolver, OpResolver};
    pub use crate::transform::optimize::{cse, dce, optimize};
    pub use crate::validate::depth::{
        LimitState, DEFAULT_MAX_CALL_DEPTH, DEFAULT_MAX_NESTING_DEPTH, DEFAULT_MAX_NODE_COUNT,
    };
    pub use crate::validate::validate::validate;
    pub use crate::validate::validation_error::ValidationError;
}

pub mod memory_model;
pub use memory_model::MemoryOrdering;
/// Driver-independent dialect lookup contracts.
pub mod dialect_lookup;
/// Link-time registry for community dialect packs.
pub mod extern_registry;
/// Endian-fixed encode/decode helpers for `Expr::Opaque` / `Node::Opaque` payloads.
pub mod opaque_payload;

/// P4.1 — AlgebraicLaw inventory + optimizer dispatch. Ops declare
/// their algebraic laws via `inventory::submit!`; optimizer passes
/// consult the registry to canonicalize operand order, fold
/// identities, and fuse associative chains.
pub mod algebraic_law_registry;
pub use algebraic_law_registry::{
    has_law, is_associative, is_commutative, laws_for_op, AlgebraicLaw, AlgebraicLawRegistration,
};

/// Packed AST (VAST) wire layout + host-side tree walks (`docs/parsing-and-frontends.md`).
pub mod vast;

/// P7.5 — Graph-IR compatibility bridge. Pure view over the
/// statement-IR `Program`; lossless lifting + lowering preserve
/// wire-format bytes under canonicalize. Optimization passes that
/// need DAG-shaped IR (auto-fusion, reaching-defs, sparse-region
/// analysis) operate on this view without changing the stable
/// wire format.
pub mod graph_view;
pub use dialect_lookup::{
    dialect_lookup, install_dialect_lookup, intern_string, AttrSchema, AttrType, Category,
    DialectLookup, InternedOpId, LoweringCtx, LoweringTable, MetalBuilder, MetalModule,
    NagaBuilder, OpDef, PtxBuilder, PtxModule, ReferenceKind, Signature, SpirvBuilder, TypedParam,
};
pub use extern_registry::{
    all_ops as all_extern_ops, dialects as extern_dialects,
    ops_in_dialect as extern_ops_in_dialect, verify as verify_extern_registry, ExternDialect,
    ExternOp, ExternVerifyError,
};
pub use graph_view::{
    from_graph, to_graph, DataEdge, DataflowKind, EdgeKind, GraphNode, GraphValidateError,
    NodeGraph,
};

// V7-API-017: `ir_inner` is intentionally private — the public surface
// re-exports through `pub mod ir` above. The internal name is pinned by
// the `vyre_macros::vyre_ast_registry!` proc-macro, which emits literal
// `crate::ir_inner::model::*` paths for the generated decoder cascades.
// Renaming `ir_inner` to `ir` requires a coordinated proc-macro rewrite
// + every dialect that uses `vyre_ast_registry!` recompiling against the
// new path. Tracked for the next semver-major.
mod ir_inner {
    pub mod model;
}
/// Region-level composition metadata shared by validation and optimizer passes.
pub mod composition;
/// CPU reference operation contract.
pub mod cpu_op;
/// CPU reference implementations shared between interpreter and ops.
pub mod cpu_references;
/// Host-side IR engine helpers (prefix arrays, token filters).
pub mod engine;
/// Open-IR extension surface (Opaque resolvers, extension ids, registrations).
pub mod extension;
/// Legacy lower helpers (transition surface pending driver-tier extraction).
pub mod lower;
/// Match-result scratch types used by scan engines.
pub mod match_result;
/// Pass-orchestration optimizer framework.
pub mod optimizer;
/// Binary wire format + canonical text serialization.
pub mod serial;
/// IR → IR passes: inline, cse, dce, parallelism, compiler primitives.
pub mod transform;
/// Structural + semantic validation of vyre `Program`s.
pub mod validate;
/// Visitor traits + blanket adapters routing Expr/Node variants.
pub mod visit;

/// Program → substrate-neutral execution planning for fusion, readback,
/// provenance, autotune, and accuracy guard decisions.
pub mod execution_plan;
/// Program → required-capability analysis (used by backends and conform
/// harnesses to skip ops whose lowering needs a capability the backend
/// does not advertise, without maintaining hardcoded exempt lists).
pub mod program_caps;

/// Unified error type for validation, wire format, lowering, and execution.
pub mod error;
pub use error::{Error, Result};

/// Test utilities shared across optimizer and transform test suites.
#[cfg(test)]
pub mod test_util;
