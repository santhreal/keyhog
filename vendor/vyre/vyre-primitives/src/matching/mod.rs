//! Tier 2.5 byte/text scan primitives (DFA, substring, filters).
//!
//! The path IS the interface. Callers write
//! `vyre_primitives::matching::bracket_match::bracket_match(...)` —
//! explicit paths; no wildcard re-exports.
//!
//! See `docs/primitives-tier.md` and `docs/lego-block-rule.md`.

/// Back-compat module tree for older `matching::ops::*` imports.
pub mod ops;

/// Bounded-stack bracket-pair detector.
pub mod bracket_match;

/// Span-region dedup primitive. Collapses same-pid overlapping or
/// touching `(pid, start, end)` triples into a representative span.
/// Every multimatch consumer in the workspace was reimplementing this
/// — one primitive replaces all of them.
pub mod region;

mod dfa_compile;

pub use bracket_match::{
    bracket_match, cpu_ref as bracket_match_cpu_ref, pack_u32 as pack_bracket_u32, CLOSE_BRACE,
    MATCH_NONE, OPEN_BRACE, OTHER,
};
pub use dfa_compile::{
    dfa_compile, dfa_compile_with_budget, CompiledDfa, DfaCompileError, DfaWireError,
    DEFAULT_DFA_BUDGET_BYTES,
};
pub use region::{
    dedup_regions_cpu, dedup_regions_flag_program, dedup_regions_inplace, RegionTriple,
};
