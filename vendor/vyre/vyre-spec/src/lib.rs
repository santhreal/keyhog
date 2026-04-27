#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
//! vyre-spec is the machine-checkable frozen data contract for the vyre GPU
//! compute IR. Any backend may depend on vyre-spec alone to prove conformance
//! without depending on vyre itself.
//!
//! This crate is intentionally data-only. It has no dependency on `vyre` or
//! `vyre`; backend vendors can use these types as the stable contract
//! for conformance proofs. Example: a conformance runner can read an
//! [`OpSignature`] and verify the byte width expected by a backend primitive.

/// Adversarial input descriptors — hostile payloads every op must reject or handle.
/// Specification element.
/// Specification element.
pub mod adversarial_input;
/// Algebraic law primitives — associativity, identity, commutativity declarations.
/// Specification element.
/// Specification element.
pub mod algebraic_law;
/// Canonical catalog of every algebraic law tagged to operations.
/// Specification element.
/// Specification element.
pub mod all_algebraic_laws;
/// Atomic operation enum — the bounded set of read-modify-write primitives.
/// Specification element.
/// Specification element.
pub mod atomic_op;
/// Binary operator enum — all element-wise two-operand primitives.
/// Specification element.
/// Specification element.
pub mod bin_op;
/// Buffer access mode (ReadOnly / WriteOnly / ReadWrite) + enforcement helpers.
/// Specification element.
/// Specification element.
pub mod buffer_access;
/// Iterator returning op ids grouped by their `Category`.
/// Specification element.
/// Specification element.
pub mod by_category;
/// Reverse index from op id string to its canonical descriptor.
/// Specification element.
/// Specification element.
pub mod by_id;
/// Conformance invariant: the op catalog enumerates every known id.
/// Specification element.
/// Specification element.
pub mod catalog_is_complete;
/// Category enum (A/B/C) + backend-availability predicates.
/// Specification element.
/// Specification element.
pub mod category;
/// Calling conventions between CPU host and GPU kernels.
/// Specification element.
/// Specification element.
pub mod convention;
/// Primitive data-type enum (U32/F32/Bool/etc.) + size helpers.
/// Specification element.
/// Specification element.
pub mod data_type;
/// Invariants the engine itself must preserve (wire round-trip, CSE stability, …).
/// Specification element.
/// Specification element.
pub mod engine_invariant;
/// Frozen catalog of core `Expr` variant names used by coverage tests.
/// Specification element.
/// Specification element.
pub mod expr_variant;
/// Dialect extension descriptor — marks non-core ops carried by extensions.
/// Specification element.
/// Specification element.
pub mod extension;
/// Floating-point type subset (F16/F32/F64) with associated properties.
/// Specification element.
/// Specification element.
pub mod float_type;
/// Golden reference samples — tiny fixtures every backend must reproduce exactly.
/// Specification element.
/// Specification element.
pub mod golden_sample;
/// Table of hardware intrinsics exposed by vyre-intrinsics.
/// Specification element.
/// Specification element.
pub mod intrinsic_table;
/// Abstract invariant type + provenance tracking.
/// Specification element.
/// Specification element.
pub mod invariant;
/// Classification buckets grouping related invariants (numeric, memory, …).
/// Specification element.
/// Specification element.
pub mod invariant_category;
/// Catalog of invariants every registered op is checked against.
/// Specification element.
/// Specification element.
pub mod invariants;
/// Known-answer test vector type — deterministic input/output pairs.
/// Specification element.
/// Specification element.
pub mod kat_vector;
/// Canonical catalog of algebraic laws exposed via `law_catalog()`.
/// Specification element.
/// Specification element.
pub mod law_catalog;
/// Layer enum (IR / backend / runtime) — coarse module placement.
/// Specification element.
/// Specification element.
pub mod layer;
/// Metadata classification for `OpMetadata` entries.
/// Specification element.
/// Specification element.
pub mod metadata_category;
/// Monotonicity direction (increasing / decreasing / none) for op outputs.
/// Specification element.
/// Specification element.
pub mod monotonic_direction;
/// Operation contract: capability requirements, determinism, cost hints.
/// Specification element.
/// Specification element.
pub mod op_contract;
/// Op metadata struct — human-facing description and discoverability hooks.
/// Specification element.
/// Specification element.
pub mod op_metadata;
/// Op signature — stable type profile every backend lowers against.
/// Specification element.
/// Specification element.
pub mod op_signature;
/// Packed graph node kinds for language-agnostic analysis.
/// Specification element.
/// Specification element.
pub mod pg_node_kind;
/// Ternary operator enum — select, FMA, mask-merge.
/// Specification element.
/// Specification element.
pub mod ternary_op;
/// Structured test descriptor — op id, input sampler, expected shape.
/// Specification element.
/// Specification element.
pub mod test_descriptor;
#[cfg(test)]
mod tests;
/// Unary operator enum — single-operand element-wise primitives.
/// Specification element.
/// Specification element.
pub mod un_op;
/// Conformance verification driver — runs the law + invariant battery.
/// Specification element.
/// Specification element.
pub mod verification;

/// See [`adversarial_input::AdversarialInput`].
/// Specification element.
/// Specification element.
pub use adversarial_input::AdversarialInput;
/// See [`algebraic_law::AlgebraicLaw`].
/// Specification element.
/// Specification element.
pub use algebraic_law::{AlgebraicLaw, LawCheckFn};
/// See [`all_algebraic_laws::all_algebraic_laws`].
/// Specification element.
/// Specification element.
pub use all_algebraic_laws::all_algebraic_laws;
/// See [`atomic_op::AtomicOp`].
/// Specification element.
/// Specification element.
pub use atomic_op::AtomicOp;
/// See [`bin_op::BinOp`].
/// Specification element.
/// Specification element.
pub use bin_op::BinOp;
/// See [`buffer_access::BufferAccess`].
/// Specification element.
/// Specification element.
pub use buffer_access::BufferAccess;
/// See [`by_category::by_category`].
/// Specification element.
/// Specification element.
pub use by_category::by_category;
/// See [`by_id::by_id`].
/// Specification element.
/// Specification element.
pub use by_id::by_id;
/// See [`catalog_is_complete::catalog_is_complete`].
/// Specification element.
/// Specification element.
pub use catalog_is_complete::catalog_is_complete;
/// See [`category::Category`] + backend-availability helpers.
/// Specification element.
/// Specification element.
pub use category::{BackendAvailability, BackendAvailabilityPredicate, Category};
/// See [`convention::Convention`].
/// Specification element.
/// Specification element.
pub use convention::Convention;
/// See [`data_type::DataType`].
/// Specification element.
/// Specification element.
pub use data_type::DataType;
/// See [`engine_invariant::EngineInvariant`].
/// Specification element.
/// Specification element.
pub use engine_invariant::{EngineInvariant, InvariantId};
/// See [`expr_variant::expr_variants`].
/// Specification element.
/// Specification element.
pub use expr_variant::expr_variants;
/// See [`float_type::FloatType`].
/// Specification element.
/// Specification element.
pub use float_type::FloatType;
/// See [`golden_sample::GoldenSample`].
/// Specification element.
/// Specification element.
pub use golden_sample::GoldenSample;
/// See [`intrinsic_table::IntrinsicTable`].
/// Specification element.
/// Specification element.
pub use intrinsic_table::IntrinsicTable;
/// See [`invariant::Invariant`].
/// Specification element.
/// Specification element.
pub use invariant::Invariant;
/// See [`invariant_category::InvariantCategory`].
/// Specification element.
/// Specification element.
pub use invariant_category::InvariantCategory;
/// See [`invariants::invariants`].
/// Specification element.
/// Specification element.
pub use invariants::{empty_test_family, invariants};
/// See [`kat_vector::KatVector`].
/// Specification element.
/// Specification element.
pub use kat_vector::KatVector;
/// See [`law_catalog::law_catalog`].
/// Specification element.
/// Specification element.
pub use law_catalog::law_catalog;
/// See [`layer::Layer`].
/// Specification element.
/// Specification element.
pub use layer::Layer;
/// See [`metadata_category::MetadataCategory`].
/// Specification element.
/// Specification element.
pub use metadata_category::MetadataCategory;
/// See [`monotonic_direction::MonotonicDirection`].
/// Specification element.
/// Specification element.
pub use monotonic_direction::MonotonicDirection;
/// See [`op_contract::OperationContract`] and its component types.
pub use op_contract::{
    CapabilityId, CostHint, DeterminismClass, OperationContract, SideEffectClass,
};
/// See [`op_metadata::OpMetadata`].
/// Specification element.
/// Specification element.
pub use op_metadata::OpMetadata;
/// See [`op_signature::OpSignature`].
/// Specification element.
/// Specification element.
pub use op_signature::OpSignature;
/// See [`pg_node_kind::PgNodeKind`].
/// Specification element.
/// Specification element.
pub use pg_node_kind::PgNodeKind;
/// See [`ternary_op::TernaryOp`].
/// Specification element.
/// Specification element.
pub use ternary_op::TernaryOp;
/// See [`test_descriptor::TestDescriptor`].
/// Specification element.
/// Specification element.
pub use test_descriptor::TestDescriptor;
/// See [`un_op::UnOp`].
/// Specification element.
/// Specification element.
pub use un_op::UnOp;
/// See [`verification::Verification`].
/// Specification element.
/// Specification element.
pub use verification::Verification;

/// Intrinsic descriptors.
/// Specification element.
/// Specification element.
pub mod intrinsic_descriptor;
/// See [`intrinsic_descriptor::IntrinsicDescriptor`] and its identifying types.
pub use intrinsic_descriptor::{
    Backend, BackendId, BackendKind, CpuFn, ExtensionBackend, IntrinsicDescriptor,
};
