//! Core scanning engine.
//!
//! # The one flow
//!
//! Every scan is the same pipeline. The ONLY thing that varies is *phase 1*
//! (which detectors could fire where), produced on the CPU by Hyperscan or on
//! the GPU by VYRE's literal region-presence backend. Everything downstream is
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
//! dispatch in [`gpu_region_dispatch`]. Selecting an exact GPU backend
//! (`--backend gpu-cuda` or `--backend gpu-wgpu`)
//! routes the batch path through it. The no-backend library API is the portable
//! CPU reference; the CLI passes its persisted fastest-correct route explicitly.
//! A requested GPU path never turns failure into an empty successful result.
//!
//! # Where each method lives
//!
//! `CompiledScanner` construction and public lifecycle methods live under
//! `compiled_scanner/`. Execution methods live here, split by responsibility.
//! To find a method, look here first:
//!
//! - `scan` / `scan_with_backend` / `scan_with_deadline*` .... compiled_scanner/runtime.rs
//! - `scan_inner` ................................................................................ scan.rs
//! - `scan_coalesced` / `compute_coalesced_triggers` / `scan_coalesced_phase2` .................. scan_coalesced.rs
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
//! - compile (build the scanner, acquire backends) .... compiled_scanner/compile.rs

mod backend;
mod backend_dispatch;
mod backend_prepared;
mod backend_triggered;
mod boundary;
pub(crate) use boundary::derive_pattern_boundary_context;
#[cfg(feature = "gpu")]
pub(crate) use boundary::regex_match_byte_upper_bound;
#[cfg(test)]
pub(crate) use boundary::scan_chunk_boundaries as scan_chunk_boundaries_for_test;
mod csr;
pub(crate) use csr::CsrU32;
mod extract;
mod gpu_cache;
#[cfg(all(test, feature = "gpu"))]
pub(crate) use gpu_cache::gpu_matcher_cache_dir_from_base;
mod gpu_artifacts;
mod gpu_forced;
pub(crate) use gpu_forced::require_selected_gpu_stack;
mod gpu_forced_helpers;
mod gpu_lazy;
mod gpu_lazy_helpers;
mod gpu_literal_scratch;
#[cfg(feature = "gpu")]
pub(crate) mod gpu_region_batch;
#[cfg(feature = "gpu")]
mod gpu_region_dispatch;
#[cfg(feature = "gpu")]
mod gpu_region_dispatch_helpers;
#[cfg(feature = "gpu")]
mod gpu_resident_presence;
#[cfg(feature = "gpu")]
pub(crate) use gpu_resident_presence::GpuResidentPresenceSlot;
mod gpu_stack;
mod hot_patterns;
pub(crate) mod phase2;
mod phase2_anchor;
#[cfg(test)]
pub(crate) use phase2_anchor::required_prefix_literals as phase2_required_prefix_literals_for_test;
pub(crate) use phase2_anchor::Phase2AnchorIndex;
// Always-on re-export (NOT cfg(test)) so `crate::testing`: which is compiled
// even when the crate is linked as a dependency of the integration-test binary,
// where `cfg(test)` is false for this crate, can classify confirmed patterns by
// the SAME required-prefix predicate `ConfirmedAnchorIndex` uses (backlog 4786
// localization-ceiling analysis).
pub(crate) use phase2_anchor::{
    required_prefix_literals_with_cap, CONFIRMED_MAX_LITERALS_PER_PATTERN,
};
mod phase1_admission;
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
#[cfg(feature = "gpu")]
pub(crate) use phase2_gpu_dfa::Phase2GpuDfaCatalogCache;
#[cfg(feature = "simd")]
mod phase2_hs;
#[cfg(all(test, feature = "simd"))]
pub(crate) use phase2_hs::hs_prefilter_requires_host_regex as hs_prefilter_requires_host_regex_for_test;
#[cfg(all(test, feature = "simd"))]
pub(crate) use phase2_hs::Phase2HsEngine;
pub(crate) mod gpu_input_budget;
mod phase2_prefilter;
pub(crate) mod phase2_truncate;
mod process;
pub(crate) mod profile;
mod scan;
mod scan_coalesced;
pub(crate) mod scan_filters;
mod scan_inner_profile;
mod scan_postprocess;
pub(crate) use scan_postprocess::{
    build_confirmed_suffix_gate, confirmed_anchor::ConfirmedAnchorIndex,
};
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
// Coalesced-attribution primitive. No production scan-pipeline consumer yet;
// its only user is the doc-hidden `testing::segment_attribution` facade, which
// now RE-EXPORTS this single owner (`pub use`) instead of carrying a second
// hand-copied body (ONE-PLACE / Law-11). Kept `pub(crate)` with `pub` items so
// the re-export can widen them to the testing facade's public surface.
pub(crate) mod segment_attribution;
pub(crate) mod trigger_bitmap;
mod windowed;
mod windowed_support;

// `build_simd_scanner` only exists under the `simd` (Hyperscan) feature; its
// sole call site in `compiled_scanner/compile.rs` is `#[cfg(feature = "simd")]`
// too. Gate the
// import to match, or non-simd builds (the `portable` feature used for the
// macOS/Windows/musl release assets) fail with E0432.
#[cfg(feature = "simd")]
pub(crate) use backend_prepared::build_simd_scanner;
pub(crate) use backend_prepared::code_lines_from_offsets;
pub(crate) use backend_prepared::PreparedChunk;
#[cfg(test)]
pub(crate) use boundary::scan_chunk_boundaries;
pub use gpu_artifacts::{
    compile_gpu_literal_artifacts, compile_gpu_literal_artifacts_default,
    gpu_literal_artifact_cache_dir, GpuLiteralArtifact, GpuLiteralArtifacts,
};
#[cfg(test)]
pub(crate) use gpu_forced_helpers::gpu_forced_unavailable_message;
pub use gpu_input_budget::{
    gpu_batch_input_limit, gpu_batch_input_limit_bounds, set_gpu_batch_input_limit,
};
#[cfg(test)]
pub(crate) use phase2::{phase2_gate_stats_dump, phase2_mark_stats, phase2_mark_stats_reset};
pub use profile::{
    dump as profile_dump, reset as profile_reset, set_perf_trace_enabled, set_profile_enabled,
};
#[cfg(test)]
pub(crate) use scan_inner_profile::scan_inner_profile_dump;
#[cfg(test)]
pub(crate) use scan_postprocess::decode_profile_dump;
pub(crate) use scan_postprocess_suffix_gate::suffix_gate_literals;
pub(crate) use windowed::{reject_oversized_window_chunk, MAX_WINDOW_CHUNK_BYTES};
pub(crate) use windowed_support::{absolute_line, absolute_offset, ceil_char_boundary};
pub use windowed_support::{
    floor_char_boundary, line_number_for_offset, next_window_offset, record_window_match,
    window_chunk, window_end_offset, window_ranges,
};

use crate::compiled_scanner::{GpuBackendAcquisitionFailure, GpuBackendPeers};
use crate::pipeline::*;
use crate::types::*;
use aho_corasick::AhoCorasick;
use keyhog_core::{Chunk, RawMatch};
use std::sync::Arc;
use std::sync::OnceLock;

/// Per-pattern hard iteration cap shared by every inner match-walk loop in the
/// engine (`extract.rs`'s confirmed/anchored extractors and
/// `phase2_anchor_scan.rs`'s anchored phase-2 walk).
///
/// The deadline path (`LoopDeadline` + `loop_expired_on_cadence`) is the
/// operator's wall-clock defense; this cap is the per-pattern budget that fires
/// even when `--timeout` is unset (`deadline == None`). Without it a single
/// regex matching every byte on a 64 MiB chunk (false-prefix storm, catastrophic
/// backtracking) would loop ~64M times. 1M iterations per pattern is ~6 orders of
/// magnitude above any legitimate detector's per-chunk match count, so a real
/// scan never reaches it. Defined once here so the three walk sites can never
/// drift apart (each used to carry its own byte-identical copy).
pub(crate) const MAX_INNER_LOOP_ITERS: usize = 1_000_000;

/// Minimum chunk length (bytes) at or above which the bigram-bloom prefilter is
/// consulted to skip a chunk. Below this length the bloom is bypassed and the
/// chunk always advances to scanning: short chunks are too cheap to scan for the
/// prefilter to earn its keep, and dropping one on a bloom miss risks a
/// false-negative for negligible speed gain.
///
/// Defined once here so the two admission sites that gate on it, the coalesced
/// phase-1 producer ([`scan_coalesced`]) and the single-chunk entry
/// ([`crate::compiled_scanner`]), can never carry divergent copies of the
/// threshold (each
/// used to hardcode a bare `64`).
pub(crate) const BIGRAM_BLOOM_MIN_CHUNK_BYTES: usize = 64;

pub(crate) use phase1_admission::Phase1Admission;
pub use phase1_admission::{Phase1AdmissionPlan, Phase1AdmissionSummary};

pub struct CompiledScanner {
    pub(crate) fragment_cache: crate::fragment_cache::FragmentCache,
    pub(crate) ac: Option<AhoCorasick>,
    pub(crate) gpu_backends: GpuBackendPeers,
    pub(crate) gpu_acquisition_failures: Vec<GpuBackendAcquisitionFailure>,
    pub(crate) gpu_literals: Option<Arc<Vec<Vec<u8>>>>,
    #[cfg(feature = "gpu")]
    pub(crate) gpu_max_literal_len: usize,
    pub(crate) gpu_matcher: OnceLock<Option<vyre_libs::scan::GpuLiteralSet>>,
    #[cfg(feature = "gpu")]
    pub(crate) gpu_resident_presence_cuda:
        std::sync::Mutex<gpu_resident_presence::GpuResidentPresenceSlot>,
    #[cfg(feature = "gpu")]
    pub(crate) gpu_resident_presence_wgpu:
        std::sync::Mutex<gpu_resident_presence::GpuResidentPresenceSlot>,
    pub(crate) gpu_last_degrade_reason: std::sync::Mutex<Option<String>>,
    pub(crate) gpu_degrade_count: std::sync::atomic::AtomicU64,
    /// One-time backend-neutral GPU literal-program preparation measured by
    /// the canonical autoroute sweep. The sweep reuses that immutable program
    /// but adds this cost to every GPU one-shot observation.
    pub(crate) autoroute_gpu_shared_cold_ns: std::sync::atomic::AtomicU64,
    pub(crate) static_intern: Arc<crate::static_intern::StaticInterner>,
    /// One detector-indexed runtime owner for interned identity, execution,
    /// entropy, key material, suppression, shape, companion, weak-anchor, and
    /// ML policy compiled from the detector TOMLs. Global matchers still span
    /// detectors, but candidate execution reaches detector-local behavior only
    /// through this plan.
    pub(crate) detector_plans: crate::detector_plan::CompiledDetectorPlans,
    /// Normalized assignment-key names owned by service-specific named
    /// detectors, e.g. `segment_write_key`. The generic assignment bridge uses
    /// this to avoid emitting a weaker generic finding for an LHS that a loaded
    /// named detector explicitly owns.
    pub(crate) generic_named_assignment_keywords: Vec<Arc<str>>,
    /// Generic assignment candidate generator compiled from this scanner's
    /// detector corpus. Both its keyword vocabulary and capture ceiling are
    /// detector-owned, so custom corpora cannot drift from the shipped global
    /// defaults or truncate an overlength credential prefix.
    pub(crate) generic_assignment_re: Option<regex::Regex>,
    /// Corpus-specific prefilter compiled from the same detector keywords as
    /// `generic_assignment_re`. It must never read the embedded global corpus
    /// when this scanner was constructed from custom detectors.
    pub(crate) generic_keyword_stems: Option<phase2_generic::keywords::GenericKeywordStemSet>,
    /// GPU generic-keyword positions are produced from the embedded literal
    /// program. They are valid only when this scanner's derived vocabulary is
    /// exactly the embedded vocabulary.
    pub(crate) generic_gpu_positions_compatible: bool,
    /// Compiled generic-assignment keyword → owning generic `Phase2Generic`
    /// detector index. Replaces the per-candidate linear `detectors.iter()
    /// .find(...)` scan in the generic value-shape path with an O(1) lookup that
    /// preserves the exact first-match-by-exact-or-normalized semantics. Built
    /// ONCE at construction (see [`crate::generic_keyword_owner::GenericOwningDetectorIndex`]).
    pub(crate) generic_owning_detector: crate::generic_keyword_owner::GenericOwningDetectorIndex,
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
    /// Per-`ac_map` bit for confirmed regexes whose detector-owned
    /// `simdsieve_prefixes` can already emit the same candidate directly.
    pub(crate) hot_confirmed_by_pattern: Vec<bool>,
    /// Shared-anchor localization index over the confirmed `ac_map`. Eligible
    /// triggered patterns are verified at required-prefix candidate positions
    /// instead of each walking the whole scan window; non-eligible patterns keep
    /// the whole-chunk path.
    pub(crate) confirmed_anchor_index:
        Option<scan_postprocess::confirmed_anchor::ConfirmedAnchorIndex>,
    pub(crate) prefix_propagation: CsrU32,
    pub(crate) phase2_patterns: Vec<(CompiledPattern, Vec<String>)>,
    pub(crate) same_prefix_patterns: CsrU32,
    pub(crate) phase2_keyword_ac: Option<AhoCorasick>,
    pub(crate) phase2_keyword_to_patterns: CsrU32,
    pub(crate) phase2_keyword_count: usize,
    /// GPU region-presence literal rows appended after detector literals and
    /// phase-2 keyword rows. These are the literals backing the always-active
    /// phase-2 anchor AC; an all-zero row segment proves that AC has no possible
    /// candidates for the chunk.
    pub(crate) phase2_always_anchor_literal_count: usize,
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
    /// Resolved detector-owned hot-pattern slots. Each row bundles the prefix, precise
    /// validator AND its canonical `ac_map` delegate together, so a slot's
    /// validation target and emission target can never be indexed apart and so
    /// can never drift, they were two parallel `Vec`s read by the same
    /// `pattern_idx` before, an unauditable coupling. The hot fast-path runs each
    /// literal-prefix candidate through `slot.validator` before emitting (so it
    /// can never surface a token the detector's own regex rejects, the length
    /// floor alone let `ghp_…_…`/`xoxp-123-456-789-abc` through) and delegates
    /// the survivor to `ac_map[slot.ac_map_index]` via `process_match`. A slot's
    /// Built once by `compiled_scanner::compile_helpers::build_hot_pattern_slots`.
    #[cfg(feature = "simdsieve")]
    pub(crate) hot_pattern_slots: Vec<crate::simdsieve_prefilter::HotPatternSlot>,
    /// Detector-indexed entropy identities declared by the active TOML corpus.
    /// This keeps every active generic owner on its own identity without a
    /// scanner-global class table or detector-ID branch. A missing entry is a
    /// compile-time corpus error and is never replaced with a guessed label.
    pub config: ScannerConfig,
    pub(crate) alphabet_screen: Option<crate::alphabet_filter::AlphabetScreen>,
    pub(crate) bigram_bloom: crate::bigram_bloom::BigramBloom,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<CompiledScanner>; // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
};

#[cfg(test)]
mod max_inner_loop_iters_tests {
    use super::MAX_INNER_LOOP_ITERS;
    use crate::deadline::HOT_LOOP_DEADLINE_CADENCE;

    /// The canonical per-pattern hard cap is exactly the value the three engine
    /// walk sites (`extract.rs` ×2, `phase2_anchor_scan.rs`) used to each hardcode.
    /// If this drifts, an adversarial chunk's per-pattern iteration budget changes
    /// silently for every walk at once (pin the concrete value).
    #[test]
    fn canonical_cap_is_one_million() {
        assert_eq!(MAX_INNER_LOOP_ITERS, 1_000_000);
    }

    /// The wall-clock deadline is re-checked once every `HOT_LOOP_DEADLINE_CADENCE`
    /// iterations, so a walk that runs to the hard cap performs exactly
    /// `MAX_INNER_LOOP_ITERS / HOT_LOOP_DEADLINE_CADENCE` deadline checks. The cap
    /// must be an exact whole multiple of the cadence (last check lands on the cap)
    /// and yield the concrete 15625 checks, proving the deadline path can still
    /// abort well before the hard cap is reached.
    #[test]
    fn cap_is_whole_multiple_of_deadline_cadence() {
        assert_eq!(HOT_LOOP_DEADLINE_CADENCE, 64);
        assert_eq!(MAX_INNER_LOOP_ITERS % HOT_LOOP_DEADLINE_CADENCE, 0);
        assert_eq!(MAX_INNER_LOOP_ITERS / HOT_LOOP_DEADLINE_CADENCE, 15_625);
    }

    /// The bigram-bloom admission threshold shared by the coalesced producer and
    /// the single-chunk entry is exactly the bare `64` those two sites used to
    /// hardcode. Pin the concrete value: if it drifts, both admission gates
    /// change their short-chunk skip boundary at once and a silent recall shift
    /// would be invisible without this lock.
    #[test]
    fn bigram_bloom_min_chunk_bytes_is_sixty_four() {
        assert_eq!(super::BIGRAM_BLOOM_MIN_CHUNK_BYTES, 64);
    }

    /// The unbounded/entropy cross-seam reassembly cap replaced a `usize::MAX`
    /// full-chunk splice (O(pairs x chunk_bytes) rescan). It is pinned to the
    /// FilesystemSource window overlap so the seam covers exactly the straddle
    /// range the overlap design assumes catchable; drifting it silently changes
    /// boundary recall AND the per-pair reassembly cost.
    #[test]
    fn boundary_seam_cap_matches_window_overlap() {
        assert_eq!(
            super::boundary::MAX_BOUNDARY_SEAM_BYTES,
            crate::types::WINDOW_OVERLAP_BYTES
        );
        assert_eq!(super::boundary::MAX_BOUNDARY_SEAM_BYTES, 128 * 1024);
    }

    /// The no-phase-1-hit keyword-free entropy admission cap is exactly the bare
    /// `32 * 1024` the three admission sites used to inline. Pinning it locks the
    /// recall/perf boundary in ONE place: a no-hit chunk larger than this with a
    /// bare anchorless high-entropy secret is not admitted to the entropy path.
    #[test]
    fn no_hit_entropy_admission_cap_is_thirty_two_kib() {
        assert_eq!(
            super::scan_coalesced::NO_HIT_ENTROPY_ADMISSION_MAX_BYTES,
            32 * 1024
        );
    }
}
