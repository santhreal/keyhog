//! Byte and text scan helpers — substring search, DFA / Aho–Corasick. Used
//! as components inside full `vyre::Program` values (decode, graph, heuristics).
//!
//! Sub-dialects:
//! - `substring` — brute-force single-string scanner
//! - `dfa` — DFA compiler + Aho-Corasick multi-string scanner
//!
//! Flat re-exports preserved for back-compat.
//!
//! # API index
//!
//! Every public surface in this module is enumerated in [`API_INDEX`]
//! as a stable `(name, kind, feature)` triple. Consumers that need to
//! discover the engine surface programmatically — keyhog's
//! `--list-engines`, the conformance harness's coverage check, the
//! cargo-doc completeness test below — read this single const instead
//! of grepping the module tree.

/// Stable index of public exports under `vyre_libs::matching`. Each
/// entry is a `(symbol, kind, feature_gate)` triple. `feature_gate`
/// is `None` for unconditional exports and `Some("flag-name")` for
/// items behind a Cargo feature.
///
/// Keep this in sync with the `pub use` lines below. The
/// `api_index_covers_every_export` test in `tests/api_index.rs`
/// verifies that every name in [`API_INDEX`] resolves to a real
/// import path so a refactor that removes or renames a public symbol
/// fails CI loudly instead of silently leaving the index stale.
pub const API_INDEX: &[(&str, ApiKind, Option<&str>)] = &[
    // Unconditional dispatch primitives.
    ("byte_scan_dispatch_config", ApiKind::Function, None),
    ("candidate_start_dispatch_config", ApiKind::Function, None),
    ("haystack_len_u32", ApiKind::Function, None),
    ("pack_haystack_u32", ApiKind::Function, None),
    ("pack_u32_slice", ApiKind::Function, None),
    ("scan_guard", ApiKind::Function, None),
    ("unpack_match_triples", ApiKind::Function, None),
    ("DEFAULT_MAX_SCAN_BYTES", ApiKind::Const, None),
    // Engine traits + helpers.
    ("MatchScan", ApiKind::Trait, None),
    ("MatchEngineCache", ApiKind::Trait, None),
    ("ScanResult", ApiKind::Struct, None),
    ("cached_load_or_compile", ApiKind::Function, None),
    ("engine_cache_path", ApiKind::Function, None),
    // Hit-buffer helpers.
    ("compact_hits", ApiKind::Function, None),
    ("compact_hits_with_layout", ApiKind::Function, None),
    ("emit_hit", ApiKind::Function, None),
    ("emit_hit_then_compact", ApiKind::Function, None),
    ("emit_hit_then_compact_with_layout", ApiKind::Function, None),
    ("emit_hit_with_layout", ApiKind::Function, None),
    ("HIT_BUFFER_LIVE_LENGTH", ApiKind::Const, None),
    ("HIT_BUFFER_OVERFLOW_COUNT", ApiKind::Const, None),
    // Literal-set engine — unconditional.
    ("GpuLiteralSet", ApiKind::Struct, None),
    ("LiteralMatch", ApiKind::TypeAlias, None),
    ("LiteralSetWireError", ApiKind::Enum, None),
    // Cross-program fusion (re-exported from vyre-foundation).
    ("fuse_programs", ApiKind::Function, None),
    ("fuse_programs_vec", ApiKind::Function, None),
    ("FusionError", ApiKind::Enum, None),
    // matching-substring.
    (
        "substring_search",
        ApiKind::Function,
        Some("matching-substring"),
    ),
    // matching-dfa.
    ("aho_corasick", ApiKind::Function, Some("matching-dfa")),
    ("dfa_compile", ApiKind::Function, Some("matching-dfa")),
    (
        "dfa_compile_with_budget",
        ApiKind::Function,
        Some("matching-dfa"),
    ),
    ("CompiledDfa", ApiKind::Struct, Some("matching-dfa")),
    ("DfaCompileError", ApiKind::Enum, Some("matching-dfa")),
    (
        "DEFAULT_DFA_BUDGET_BYTES",
        ApiKind::Const,
        Some("matching-dfa"),
    ),
    ("DirectGpuScanner", ApiKind::Struct, Some("matching-dfa")),
    // matching-nfa.
    (
        "build_rule_pipeline",
        ApiKind::Function,
        Some("matching-nfa"),
    ),
    ("PipelineWireError", ApiKind::Enum, Some("matching-nfa")),
    ("RulePipeline", ApiKind::Struct, Some("matching-nfa")),
    // matching-regex.
    (
        "build_rule_pipeline_from_regex",
        ApiKind::Function,
        Some("matching-regex"),
    ),
    (
        "compile_regex_set",
        ApiKind::Function,
        Some("matching-regex"),
    ),
    ("CompiledRegexSet", ApiKind::Struct, Some("matching-regex")),
    ("RegexCompileError", ApiKind::Enum, Some("matching-regex")),
];

/// Item-kind tag for entries in [`API_INDEX`]. Coarse on purpose —
/// the goal is "what's the symbol shape?" not full reflection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ApiKind {
    /// Free function or method exported at module root.
    Function,
    /// `pub struct` or unit struct.
    Struct,
    /// `pub enum`.
    Enum,
    /// `pub trait`.
    Trait,
    /// `pub const`.
    Const,
    /// `pub type` alias.
    TypeAlias,
}

pub mod builders;
pub mod hit_buffer;

/// Shared GPU dispatch primitives for matching engines.
///
/// Centralises haystack-packing, length validation, dispatch geometry,
/// and match-triple unpacking so every new matcher (literal-set,
/// regex pipeline, future taint scan) reuses the same byte-level
/// plumbing instead of re-implementing it.
pub mod dispatch_io;

/// Common scan + cache traits for every matcher in this crate.
///
/// Engines implement `MatchScan` (object-safe) and `MatchEngineCache`
/// (typed errors). Consumers use `cached_load_or_compile` to wire on-
/// disk caches generically — the per-engine cache wiring keyhog
/// previously hand-rolled is now a one-line call.
pub mod engine;
pub use dispatch_io::{
    byte_scan_dispatch_config, candidate_start_dispatch_config, haystack_len_u32,
    pack_haystack_u32, pack_u32_slice, scan_guard, unpack_match_triples, DEFAULT_MAX_SCAN_BYTES,
};
pub use engine::{
    cache_path as engine_cache_path, cached_load_or_compile, MatchEngineCache, MatchScan,
    ScanResult,
};

#[cfg(feature = "matching-substring")]
pub mod substring;

#[cfg(feature = "matching-dfa")]
pub mod dfa;

/// Classic Aho-Corasick with precomputed flat `output_links`.
/// Scans in O(matches) per position, not O(states × n).
#[cfg(feature = "matching-dfa")]
pub mod classic_ac;

/// Subgroup-cooperative NFA scan helper (G1). Composes
/// `vyre_primitives::nfa::subgroup_nfa::nfa_step` into a multi-byte /
/// multi-pattern scan. Feature-gated behind `matching-nfa` so consumers
/// opt in when they need NFAs up to 1024 states with subgroup-shuffle
/// epsilon closure.
#[cfg(feature = "matching-nfa")]
pub mod nfa;

pub mod literal_set;

/// Match post-processing: dedup, entropy, and confidence in one reference pass.
pub mod post_process;

/// Generic engine + post-processor pipeline. Pairs any `MatchScan`
/// implementer with the canonical post-processing contract.
pub mod pipeline;

/// Canonical literal/regex/haystack fixture corpus shared by every
/// integration test in this crate. Public when the consumer opts into
/// `feature = "test-fixtures"`; always available inside the in-tree
/// test compilation.
#[cfg(any(test, feature = "test-fixtures"))]
pub mod test_fixtures;

#[cfg(feature = "matching-dfa")]
pub mod direct_gpu;

/// Mega-scan integrator (G-stack). Fuses the G1-G10 innovations
/// into one `RulePipeline` object: G1 NFA prefilter + G2 rule
/// fusion + G5 decode-scan workgroup handoff + G6 speculative
/// commit + G7 persistent-engine work items + G8 content-hash
/// cache key + G4 adaptive CSR/dense graph traversal + G9 CHD
/// perfect hash + G10 differential scan file selection. One
/// object surgec dispatches.
#[cfg(feature = "matching-nfa")]
pub mod mega_scan;

/// Regex AST → NfaPlan frontend. Lowers a regex string into the same
/// `(NfaPlan, transition_table, epsilon_table)` triple that
/// [`nfa::compile`] produces for literals, so every downstream component
/// (`nfa_scan` Program, `mega_scan::build`, `RulePipeline`) runs
/// unmodified. Behind `matching-regex` so consumers without the regex
/// frontend skip the `regex-syntax` dep.
#[cfg(feature = "matching-regex")]
pub mod regex_compile;

#[cfg(feature = "matching-dfa")]
pub use dfa::{
    aho_corasick, dfa_compile, dfa_compile_with_budget, CompiledDfa, DfaCompileError,
    DEFAULT_DFA_BUDGET_BYTES,
};
#[cfg(feature = "matching-dfa")]
pub use direct_gpu::DirectGpuScanner;
pub use hit_buffer::{
    compact_hits, compact_hits_with_layout, emit_hit, emit_hit_then_compact,
    emit_hit_then_compact_with_layout, emit_hit_with_layout, HIT_BUFFER_LIVE_LENGTH,
    HIT_BUFFER_OVERFLOW_COUNT,
};
pub use literal_set::{GpuLiteralSet, LiteralSetWireError, Match as LiteralMatch};
#[cfg(feature = "matching-nfa")]
pub use mega_scan::{build as build_rule_pipeline, PipelineWireError, RulePipeline};
pub use pipeline::{Pipeline, PostProcessFn};
pub use post_process::{
    post_process_cpu, shannon_entropy_bits_per_byte, try_post_process_cpu, PostProcessError,
    PostProcessedMatch,
};
#[cfg(feature = "matching-regex")]
pub use regex_compile::{
    build_rule_pipeline_from_regex, compile_regex_set, CompiledRegexSet, RegexCompileError,
};
#[cfg(feature = "matching-substring")]
pub use substring::substring_search;
// Re-export the cross-program fusion API at the matching layer so consumers
// don't have to reach into `vyre-foundation` directly.
pub use vyre_foundation::execution_plan::fusion::{fuse_programs, fuse_programs_vec, FusionError};

/// Re-export the CPU region-dedup primitive plus its GPU companion
/// so consumers (keyhog, surgec) get the canonical span-coalescing
/// helpers through `vyre_libs::matching` without taking a separate
/// dep on `vyre-primitives`. Same module path lego-block consumers
/// already import for `MatchScan` / `cached_load_or_compile`.
pub use vyre_primitives::matching::region::{
    dedup_regions_cpu, dedup_regions_flag_program, dedup_regions_inplace, RegionTriple,
};
