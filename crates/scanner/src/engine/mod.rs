//! Core scanning engine.
//!
//! # The one flow
//!
//! Every scan is the same pipeline. The ONLY thing that varies is *phase 1*
//! (which detectors could fire where) — produced on the CPU by Hyperscan or on
//! the GPU by Vyre's literal region-presence backend. Everything downstream is
//! shared:
//!
//! ```text
//!   files ─▶ phase 1: trigger production         (swappable backend)
//!           ├─ CPU: compute_coalesced_triggers   (Hyperscan prefilter)   scan_coalesced.rs
//!           └─ GPU: scan_coalesced_gpu_region_presence (batched region-presence) gpu_region_dispatch.rs
//!                       │  one bitmap per chunk: "which detectors may match here"
//!                       ▼
//!           phase 2: scan_coalesced_phase2       (THE shared tail)        scan_coalesced.rs
//!             • windowing (scan_windowed / triggered windows)               windowed.rs
//!             • per-chunk extraction (scan_prepared_with_triggered)        backend_triggered.rs
//!                 confirmed → phase2 capture → generic → entropy → ML
//!             • post-process: suppression, dedup, confidence, decode/ML    scan_postprocess.rs
//!             • cross-chunk boundary reassembly (scan_chunk_boundaries)    boundary.rs
//! ```
//!
//! There is exactly ONE production on-GPU trigger producer: the region-presence
//! dispatch in [`gpu_region_dispatch`]. Selecting a GPU backend (`--backend gpu`)
//! routes the batch path through it;
//! the default backend is the CPU Hyperscan path. The GPU path degrades LOUDLY
//! to CPU on any failure (never a silent empty result — Law 10).
//!
//! # Where each method lives (the `CompiledScanner` god-object is split by job)
//!
//! `CompiledScanner` is one type whose `impl` blocks are spread across this
//! directory by responsibility. To find a method, look here first:
//!
//! - `scan` / `scan_with_backend` / `scan_with_deadline*` ............ mod.rs (public entry)
//! - `scan_inner` ................................................................................ scan.rs
//! - `scan_coalesced` / `compute_coalesced_triggers` / `scan_coalesced_phase2` .................. scan_coalesced.rs
//! - no-hit fragment reassembly for the shared tail .............................................. scan_no_hit_reassembly.rs
//! - `scan_chunks_with_backend_internal` (CPU-vs-GPU batch routing) .. backend_dispatch.rs
//! - `scan_coalesced_gpu_region_presence` (GPU trigger production) ... gpu_region_dispatch.rs
//! - GPU region reporting/throughput helpers ................. gpu_region_dispatch_helpers.rs
//! - `scan_prepared_with_triggered` / `collect_triggered_patterns_*` . backend_triggered.rs
//! - `scan_windowed*` (the windowing contract) .............. windowed.rs
//! - confirmed-pattern extraction ................................... extract.rs
//! - phase-2 prefilter + keyword/anchor/generic/entropy passes ...... phase2*.rs
//! - hot-pattern fast path (simdsieve) ............................. hot_patterns.rs
//! - match confidence policy ...................................... confidence::policy
//! - post-process (suppression, dedup, confidence, decode/ML) ...... scan_postprocess.rs, scan_postprocess/*
//! - cross-chunk seam reassembly ................................... boundary.rs
//! - loud GPU-degrade / fail-closed helpers ....................... gpu_forced.rs
//! - compile (build the scanner, acquire backends) ................. compile.rs

mod backend;
mod backend_dispatch;
mod backend_prepared;
mod backend_triggered;
mod boundary;
#[cfg(test)]
pub(crate) use boundary::scan_chunk_boundaries as scan_chunk_boundaries_for_test;
mod compile;
mod compiled_api;
mod csr;
pub(crate) use csr::CsrU32;
mod extract;
mod gpu_cache;
#[cfg(all(test, feature = "gpu"))]
pub(crate) use gpu_cache::gpu_matcher_cache_dir_from_base;
mod gpu_artifacts;
mod gpu_forced;
mod gpu_lazy;
mod gpu_literal_scratch;
#[cfg(feature = "gpu")]
mod gpu_region_batch;
#[cfg(feature = "gpu")]
mod gpu_region_dispatch;
#[cfg(feature = "gpu")]
mod gpu_region_dispatch_helpers;
mod gpu_stack;
mod hot_patterns;
pub(crate) mod phase2;
mod phase2_anchor;
#[cfg(test)]
pub(crate) use phase2_anchor::required_prefix_literals as phase2_required_prefix_literals_for_test;
mod phase2_anchor_scan;
mod phase2_compiled;
mod phase2_compiled_anchored;
pub(crate) mod phase2_entropy;
#[path = "phase2/first_bigram.rs"]
mod phase2_first_bigram;
pub(crate) mod phase2_generic;
mod phase2_generic_shape;
#[cfg(feature = "gpu")]
mod phase2_gpu_dfa;
#[cfg(feature = "simd")]
mod phase2_hs;
mod phase2_prefilter;
pub(crate) mod phase2_truncate;
mod process;
pub(crate) mod profile;
pub(crate) mod rule_pipeline;
mod scan;
mod scan_coalesced;
mod scan_filters;
mod scan_inner_profile;
mod scan_no_hit_reassembly;
mod scan_postprocess;
#[path = "scan_postprocess/confirmed_extract.rs"]
mod scan_postprocess_confirmed_extract;
#[path = "scan_postprocess/fragments.rs"]
mod scan_postprocess_fragments;
#[cfg(feature = "ml")]
#[path = "scan_postprocess/ml.rs"]
mod scan_postprocess_ml;
#[path = "scan_postprocess/profile.rs"]
mod scan_postprocess_profile;
#[path = "scan_postprocess/suffix_gate.rs"]
mod scan_postprocess_suffix_gate;
pub(crate) mod segment_attribution;
mod trigger_bitmap;
mod windowed;
mod windowed_support;

// `build_simd_scanner` only exists under the `simd` (Hyperscan) feature; its
// sole call site in compile.rs is `#[cfg(feature = "simd")]` too. Gate the
// import to match, or non-simd builds (the `portable` feature used for the
// macOS/Windows/musl release assets) fail with E0432.
pub(crate) use backend_prepared::PreparedChunk;
#[cfg(feature = "simd")]
pub(crate) use backend_prepared::build_simd_scanner;
pub(crate) use backend_prepared::code_lines_from_offsets;
#[cfg(test)]
pub(crate) use boundary::scan_chunk_boundaries;
pub use gpu_artifacts::{
    GpuLiteralArtifact, GpuLiteralArtifacts, compile_gpu_literal_artifacts,
    compile_gpu_literal_artifacts_default,
};
#[cfg(test)]
pub(crate) use gpu_forced::gpu_forced_unavailable_message;
#[cfg(test)]
pub(crate) use phase2::{phase2_gate_stats_dump, phase2_mark_stats, phase2_mark_stats_reset};
pub use profile::{
    dump as profile_dump, reset as profile_reset, set_perf_trace_enabled, set_profile_enabled,
};
pub use rule_pipeline::megascan_input_len;
#[cfg(test)]
pub(crate) use scan_inner_profile::scan_inner_profile_dump;
#[cfg(test)]
pub(crate) use scan_postprocess::decode_profile_dump;
pub(crate) use windowed_support::ceil_char_boundary;
pub use windowed_support::{
    floor_char_boundary, line_number_for_offset, next_window_offset, record_window_match,
    window_chunk, window_end_offset, window_ranges,
};

use crate::compiler::*;
use crate::error::Result;
use crate::pipeline::*;
use crate::types::*;
use aho_corasick::AhoCorasick;
use keyhog_core::{Chunk, DetectorSpec, RawMatch};
use std::sync::Arc;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GpuInitPolicy {
    /// Honor the resolved GPU runtime policy.
    FromRuntimePolicy,
    /// Acquire a GPU backend when hardware is present, regardless of the
    /// disabled-GPU policy. Used when the operator explicitly forces GPU.
    ForceEnabled,
    /// Skip CUDA/wgpu acquisition. Used when the selected CLI path cannot
    /// route to GPU, avoiding startup and RSS overhead without changing scan
    /// results.
    ForceDisabled,
}

pub struct CompiledScanner {
    pub(crate) fragment_cache: crate::fragment_cache::FragmentCache,
    pub(crate) ac: Option<AhoCorasick>,
    pub(crate) gpu_backend: Option<Arc<dyn vyre::VyreBackend>>,
    pub(crate) gpu_literals: Option<Arc<Vec<Vec<u8>>>>,
    pub(crate) gpu_matcher: OnceLock<Option<vyre_libs::scan::GpuLiteralSet>>,
    #[cfg(feature = "gpu")]
    pub(crate) gpu_position_literals: Option<Arc<Vec<Vec<u8>>>>,
    #[cfg(feature = "gpu")]
    pub(crate) gpu_position_matcher: OnceLock<Option<vyre_libs::scan::GpuLiteralSet>>,
    pub(crate) gpu_last_degrade_reason: std::sync::Mutex<Option<String>>,
    pub(crate) gpu_degrade_count: std::sync::atomic::AtomicU64,
    pub(crate) static_intern: Arc<crate::static_intern::StaticInterner>,
    /// Per-detector interned `(id, name, service)` metadata triple, indexed by
    /// `detector_index`. Built ONCE at scanner construction from the same
    /// frozen `StaticInterner` the per-match path used to re-hash against.
    /// Every emission site has the detector index in hand, so emitting metadata
    /// is three `Arc::clone`s (atomic refcount bumps) instead of three CHD
    /// perfect-hash lookups (2x FNV-1a + verify-hash + full string compare per
    /// field). The strings are byte-identical to `static_intern.lookup(...)`
    /// because they ARE its arena entries — see `perf_locality_intern.rs`.
    pub(crate) metadata_by_index: Vec<(Arc<str>, Arc<str>, Arc<str>)>,
    /// Per-detector `detector_weak_anchor(spec)`, indexed by `detector_index`.
    /// The weak-anchor classification is a function of the detector SPEC ONLY
    /// (its id prefix, `min_confidence`, and a regex-string scan over every
    /// pattern for a broad-identifier capture), so it is constant across every
    /// candidate that detector produces. `process_match` used to recompute it
    /// per surviving candidate — on a hot detector firing thousands of matches
    /// per chunk that re-ran `has_broad_identifier_capture` (a per-pattern regex
    /// string walk) thousands of times for an unchanging value. Resolved ONCE at
    /// construction; the per-match path indexes by `entry.detector_index`. Same
    /// pattern as `metadata_by_index`. Byte-identical to
    /// `crate::suppression::detector_weak_anchor(&detectors[i])`.
    pub(crate) detector_weak_anchor_by_index: Vec<bool>,
    /// Normalized assignment-key names owned by service-specific named
    /// detectors, e.g. `segment_write_key`. The generic assignment bridge uses
    /// this to avoid emitting a weaker generic finding for an LHS that a loaded
    /// named detector explicitly owns.
    pub(crate) generic_named_assignment_keywords: Vec<Arc<str>>,
    /// Per-`ac_map` regex byte upper bound for GPU hit-local validation. `None`
    /// means the detector regex is unbounded or unparsable by the AST bounder,
    /// so GPU validation must keep the full prepared-chunk oracle.
    #[cfg(feature = "gpu")]
    pub(crate) ac_match_upper_bounds: Vec<Option<usize>>,
    pub(crate) ac_map: Vec<CompiledPattern>,
    pub(crate) pattern_boundary_context: boundary::BoundaryContextBytes,
    /// Confirmed-pass suffix gate: AC over ac_map patterns' required suffix
    /// literals (every match ends with one). `ac_suffix_gate[i]` are pattern
    /// i's literal ids; a triggered pattern whose suffix literals are all absent
    /// from the chunk cannot match and is skipped (see `extract_confirmed_patterns`).
    pub(crate) suffix_gate_ac: Option<AhoCorasick>,
    pub(crate) ac_suffix_gate: Vec<Vec<u32>>,
    /// Per-`ac_map` bit marking confirmed Stripe secret-key regexes whose
    /// literal prefix is already emitted by the direct hot path. Built from
    /// Tier-B detector classification data at compile time so candidate
    /// extraction only pays an indexed bool load.
    pub(crate) stripe_hot_confirmed_by_pattern: Vec<bool>,
    /// Shared-anchor localization index over the confirmed `ac_map`. Eligible
    /// triggered patterns are verified at required-prefix candidate positions
    /// instead of each walking the whole scan window; non-eligible patterns keep
    /// the whole-chunk path.
    pub(crate) confirmed_anchor_index:
        Option<scan_postprocess::confirmed_anchor::ConfirmedAnchorIndex>,
    pub(crate) prefix_propagation: CsrU32,
    pub(crate) phase2_patterns: Vec<(CompiledPattern, Vec<String>)>,
    pub(crate) companions: Vec<Vec<CompiledCompanion>>,
    pub(crate) detectors: Vec<DetectorSpec>,
    /// Detector-owned credential shape rules, indexed by detector index.
    /// These come from Tier-B data so per-detector length contracts do not
    /// live as hardcoded adjudicator branches.
    pub(crate) credential_shape_by_detector_index:
        Vec<Option<crate::credential_shapes::CredentialShapeRule>>,
    pub(crate) same_prefix_patterns: CsrU32,
    pub(crate) phase2_keyword_ac: Option<AhoCorasick>,
    pub(crate) phase2_keyword_to_patterns: CsrU32,
    pub(crate) phase2_keyword_count: usize,
    /// GPU region-presence literal rows appended after detector literals and
    /// phase-2 keyword rows. These are the literals backing the always-active
    /// phase-2 anchor AC; an all-zero row segment proves that AC has no possible
    /// candidates for the chunk.
    pub(crate) phase2_always_anchor_literal_count: usize,
    /// Rows in `gpu_position_literals` for confirmed shared-anchor literals.
    /// Used only as a positioned candidate accelerator; the CPU confirmed
    /// extractor remains authoritative whenever the GPU candidate list is
    /// unavailable or capped.
    #[cfg(feature = "gpu")]
    pub(crate) confirmed_anchor_literal_count: usize,
    /// Rows in `gpu_position_literals` after confirmed-anchor rows. These
    /// mirror the generic assignment bridge's compact keyword stems and are
    /// used only as positioned line-candidate hints for that bridge.
    #[cfg(feature = "gpu")]
    pub(crate) generic_keyword_literal_count: usize,
    pub(crate) phase2_always_active_indices: Vec<usize>,
    /// Combined-RegexSet prefilter over `phase2_always_active_indices`. When
    /// present, the per-chunk phase-2 capture scan runs one linear set pass instead of
    /// every always-active pattern's regex over the whole chunk. `None` falls
    /// back to running them all (recall-identical, just slower).
    pub(crate) phase2_always_active_prefilter: Option<phase2::Phase2AlwaysActivePrefilter>,
    /// Shared-anchor localization index over the phase-2 set. When present,
    /// eligible phase-2 patterns are verified anchored at candidate positions
    /// from one shared Aho-Corasick pass instead of each walking the whole
    /// chunk; non-eligible patterns keep the whole-chunk path. `None` when no
    /// pattern is anchor-eligible. Recall-identical (see `phase2_anchor`).
    pub(crate) phase2_anchor_index: Option<phase2_anchor::Phase2AnchorIndex>,
    /// Backend-shaped GPU regex-DFA admission catalogs for prefixless
    /// always-active phase-2 patterns. Used only by the coalesced GPU route: a
    /// hit admits the chunk to the shared phase-2 tail, while misses/errors
    /// continue through CPU admission so uncovered patterns cannot be silently
    /// skipped.
    #[cfg(feature = "gpu")]
    pub(crate) phase2_gpu_dfa: phase2_gpu_dfa::Phase2GpuDfaCatalogCache,
    /// Per-scanner performance route tuning (HS vs RegexSet, anchor
    /// localization, prefilter truncation, decode focus, confirmed-suffix gate,
    /// …). Resolved from compiled defaults plus explicit per-scanner config;
    /// differential parity tests override one route on THIS scanner via
    /// [`CompiledScanner::tuning`] without touching any global state. See
    /// [`phase2::ScannerTuning`].
    pub(crate) tuning: phase2::ScannerTuning,
    #[cfg(feature = "simd")]
    pub(crate) simd_prefilter: Option<crate::simd::backend::HsScanner>,
    #[cfg(feature = "simd")]
    pub(crate) hs_index_map: CsrU32,
    /// Precise-regex validator per hot-pattern slot (index-parallel with
    /// `simdsieve_prefilter::HOT_PATTERNS`). The hot fast-path runs each
    /// literal-prefix candidate through these before emitting so it can never
    /// surface a token the detector's own regex rejects (the length floor
    /// alone let `ghp_…_…`/`xoxp-123-456-789-abc` through). `None` for the one
    /// slot with no canonical detector (square).
    #[cfg(feature = "simdsieve")]
    pub(crate) hot_pattern_validators: Vec<Option<regex::Regex>>,
    /// Canonical confirmed-pattern entry for each hot-pattern slot. `Some(i)`
    /// means the SIMD hot path is only an accelerator for `ac_map[i]` and must
    /// delegate surviving candidates through `process_match`; `None` is
    /// reserved for genuinely synthetic slots with no loaded detector.
    #[cfg(feature = "simdsieve")]
    pub(crate) hot_ac_map_index_by_index: Vec<Option<usize>>,
    /// Pre-interned `(detector_id, detector_name, service)` triple for each of
    /// the four synthetic entropy-fallback classes, indexed by
    /// `classify_entropy_detector_index` (0 generic / 1 password / 2 token /
    /// 3 api-key). The entropy fallback emits directly and used to re-intern
    /// these fixed `&'static str` constants per finding; caching the four
    /// `Arc<str>` triples once turns each emit into three `Arc::clone`s
    /// (PERF-locality_intern-1). String values are unchanged.
    #[cfg(feature = "entropy")]
    pub(crate) entropy_metadata_by_index: [(Arc<str>, Arc<str>, Arc<str>); 4],
    pub config: ScannerConfig,
    pub(crate) alphabet_screen: Option<crate::alphabet_filter::AlphabetScreen>,
    pub(crate) bigram_bloom: crate::bigram_bloom::BigramBloom,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompiledScannerRuntime {
    pub detector_count: usize,
    pub pattern_count: usize,
    pub detector_digest: u64,
    pub preferred_backend: &'static str,
    pub gpu_backend: Option<&'static str>,
    pub gpu_degrade_count: u64,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<CompiledScanner>; // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
};
