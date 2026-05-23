//! Deprecated compatibility surface for the former `vyre_libs::matching` API.
//!
//! New code should import `vyre_libs::scan`; this module remains as a real
//! source-backed tree so transition users and module-surface gates see the same
//! structure instead of an inline half-migration alias.
//!
//! **Scheduled for removal in 0.6.**

#[cfg(feature = "matching-substring")]
pub mod substring;

pub use crate::scan::{
    byte_scan_dispatch_config, cached_load_or_compile, candidate_start_dispatch_config,
    compact_hits, compact_hits_with_layout, emit_hit, emit_hit_then_compact,
    emit_hit_then_compact_with_layout, emit_hit_with_layout, engine_cache_path, fuse_programs,
    fuse_programs_vec, haystack_len_u32, pack_haystack_u32, pack_u32_slice, scan_guard,
    shannon_entropy_bits_per_byte, try_reference_post_process, try_reference_post_process_into,
    u32_words_as_le_bytes, unpack_match_triples, ApiKind, FusionError, GpuLiteralSet, LiteralMatch,
    LiteralSetWireError, MatchEngineCache, MatchScan, Pipeline, PostProcessError, PostProcessFn,
    PostProcessedMatch, ScanResult, API_INDEX, DEFAULT_MAX_SCAN_BYTES, HIT_BUFFER_LIVE_LENGTH,
    HIT_BUFFER_OVERFLOW_COUNT,
};

#[cfg(feature = "matching-dfa")]
pub use crate::scan::{
    aho_corasick, dfa_compile, dfa_compile_with_budget, CompiledDfa, DfaCompileError,
    DirectGpuScanner, DEFAULT_DFA_BUDGET_BYTES,
};

#[cfg(feature = "matching-nfa")]
pub use crate::scan::{build_rule_pipeline, PipelineWireError, RulePipeline};

#[cfg(feature = "matching-regex")]
pub use crate::scan::{
    build_rule_pipeline_from_regex, compile_regex_set, CompiledRegexSet, RegexCompileError,
};

#[cfg(feature = "matching-substring")]
pub use crate::scan::substring_search;

pub use vyre_primitives::matching::region::{
    dedup_regions_flag_program, dedup_regions_inplace, RegionTriple,
};

#[cfg(feature = "cpu-parity")]
pub use crate::scan::dedup_regions_reference;

/// Compatibility shim for the former `vyre_libs::matching::dispatch_io`
/// path. Re-exports the byte-pack / dispatch-config / unpack helpers
/// that consumers reach for when building custom matcher dispatches.
pub mod dispatch_io {
    pub use crate::scan::dispatch_io::{
        byte_scan_dispatch_config, candidate_start_dispatch_config, haystack_len_u32,
        pack_haystack_u32, pack_u32_slice, scan_guard, u32_words_as_le_bytes, unpack_match_triples,
        unpack_match_triples_into,
    };
}

/// Compatibility shim for the former `vyre_libs::matching::classic_ac`
/// path. Re-exports the bounded-ranges AC program builder + CPU
/// reference scan that the GPU AC kernel depends on.
#[cfg(feature = "matching-dfa")]
pub mod classic_ac {
    pub use crate::scan::classic_ac::{
        build_ac_bounded_ranges_program, build_ac_bounded_ranges_program_ext,
        classic_ac_bounded_ranges_program, classic_ac_bounded_ranges_program_ext,
        classic_ac_bounded_ranges_scan, classic_ac_compile, classic_ac_program, classic_ac_scan,
        classic_ac_scan_counts, ClassicAcAutomaton,
    };
}
