//! Core scanning engine.
//!
//! # The one flow
//!
//! Every scan is the same pipeline. The ONLY thing that varies is *phase 1*
//! (which detectors could fire where) — produced on the CPU by Hyperscan or on
//! the GPU by the megakernel. Everything downstream is shared:
//!
//! ```text
//!   files ─▶ phase 1: trigger production         (swappable backend)
//!           ├─ CPU: compute_coalesced_triggers   (Hyperscan prefilter)   scan.rs
//!           └─ GPU: scan_coalesced_megakernel    (batched-DFA megakernel) megakernel_dispatch.rs
//!                       │  one bitmap per chunk: "which detectors may match here"
//!                       ▼
//!           phase 2: scan_coalesced_phase2       (THE shared tail)        scan.rs
//!             • windowing (scan_chunk_or_window, >1 MiB)                   windowed.rs
//!             • per-chunk extraction (scan_prepared_with_triggered)        backend_triggered.rs
//!                 confirmed → fallback → generic → entropy → ML
//!             • post-process: suppression, dedup, confidence, decode       scan_postprocess.rs
//!             • cross-chunk boundary reassembly (scan_chunk_boundaries)    boundary.rs
//! ```
//!
//! There is exactly ONE on-GPU detection engine: the megakernel
//! ([`megakernel`] + [`megakernel_dispatch`]). Selecting a GPU backend
//! (`--backend gpu` / `KEYHOG_BACKEND=gpu`) routes the batch path through it;
//! the default backend is the CPU Hyperscan path. The GPU path degrades LOUDLY
//! to CPU on any failure (never a silent empty result — Law 10).
//!
//! # Where each method lives (the `CompiledScanner` god-object is split by job)
//!
//! `CompiledScanner` is one type whose `impl` blocks are spread across this
//! directory by responsibility. To find a method, look here first:
//!
//! - `scan` / `scan_with_backend` / `scan_with_deadline*` ............ mod.rs (public entry)
//! - `scan_coalesced` / `compute_coalesced_triggers` / `scan_coalesced_phase2` / `scan_inner` .. scan.rs
//! - `scan_chunks_with_backend_internal` (CPU-vs-GPU batch routing) .. backend_dispatch.rs
//! - `scan_coalesced_megakernel` (GPU trigger production) ............ megakernel_dispatch.rs
//! - `MegakernelCatalog` (DFA catalog build + cache + dispatch) ...... megakernel.rs
//! - `scan_prepared_with_triggered` / `collect_triggered_patterns_*` . backend_triggered.rs
//! - `scan_chunk_or_window` / `scan_windowed` (the windowing contract) windowed.rs
//! - confirmed-pattern extraction ................................... extract.rs
//! - fallback prefilter + keyword/anchor/generic/entropy passes ..... fallback*.rs
//! - hot-pattern fast path (simdsieve) ............................. hot_patterns.rs
//! - post-process (suppression, dedup, confidence, decode recursion). scan_postprocess.rs, process.rs
//! - cross-chunk seam reassembly ................................... boundary.rs
//! - loud GPU-degrade / fail-closed helpers ....................... gpu_forced.rs
//! - compile (build the scanner, acquire backends) ................. compile.rs

mod backend;
mod backend_dispatch;
mod backend_prepared;
mod backend_triggered;
pub mod boundary;
mod compile;
mod compiled_api;
mod csr;
pub(crate) use csr::CsrU32;
mod extract;
pub(crate) mod fallback;
mod fallback_anchor;
mod fallback_anchor_scan;
mod fallback_compiled;
mod fallback_compiled_anchored;
mod fallback_entropy;
mod fallback_entropy_gates;
mod fallback_entropy_helpers;
mod fallback_generic;
mod fallback_generic_shape;
#[cfg(feature = "simd")]
mod fallback_hs;
mod fallback_prefilter;
mod tuning;
pub(crate) mod fallback_truncate;
mod gpu_cache;
mod gpu_forced;
mod gpu_lazy;
#[cfg(feature = "gpu")]
pub(crate) mod megakernel;
#[cfg(feature = "gpu")]
mod megakernel_dispatch;
/// Catalog cache wire (de)serialization for [`megakernel::MegakernelCatalog`],
/// split out of `megakernel.rs` (Law 5) — a stable boundary independent of the
/// catalog build/dispatch responsibility.
#[cfg(feature = "gpu")]
mod megakernel_wire;
mod hot_patterns;
mod process;
pub(crate) mod profile;
mod rule_pipeline;
mod scan;
mod scan_filters;
mod scan_inner_profile;
mod scan_postprocess;
mod scan_postprocess_fragments;
mod scan_postprocess_profile;
mod scan_postprocess_suffix_gate;
mod scoring;
pub mod segment_attribution;
mod trigger_bitmap;
mod windowed;

// `build_simd_scanner` only exists under the `simd` (Hyperscan) feature; its
// sole call site in compile.rs is `#[cfg(feature = "simd")]` too. Gate the
// import to match, or non-simd builds (the `portable` feature used for the
// macOS/Windows/musl release assets) fail with E0432.
#[cfg(feature = "simd")]
pub(crate) use backend_prepared::build_simd_scanner;
pub(crate) use backend_prepared::PreparedChunk;
pub use fallback::{fallback_gate_stats_dump, ScannerTuning};
pub use rule_pipeline::{
    build_rule_pipeline, megascan_input_len, rule_pipeline_cached, AC_GPU_MAX_MATCHES_PER_DISPATCH,
    MEGASCAN_INPUT_LEN, MEGASCAN_INPUT_LEN_DEFAULT,
};
pub use profile::{dump as profile_dump, reset as profile_reset};
pub use scan_inner_profile::scan_inner_profile_dump;
pub use scan_postprocess::decode_profile_dump;
pub use windowed::{
    floor_char_boundary, line_number_for_offset, next_window_offset, record_window_match,
    window_chunk, window_end_offset,
};

use crate::compiler::*;
use crate::error::Result;
use crate::pipeline::*;
use crate::types::*;
use aho_corasick::AhoCorasick;
use keyhog_core::{Chunk, DetectorSpec, RawMatch};
use std::sync::Arc;
use std::sync::OnceLock;

pub use vyre_libs::scan::LiteralMatch;

/// Read `KEYHOG_PER_CHUNK_TIMEOUT_MS` and turn it into a per-chunk
/// deadline `Instant`. Returns `None` when the env var is unset or
/// malformed - the historical "scan until done" behavior.
///
/// Wired into the public `scan` / `scan_with_backend` entry points
/// so a hostile or pathological input (e.g. the Apple Silicon
/// regex-DFA construction stall surfaced during cross-platform
/// dogfood - a single 171-byte line with `var token = identifier.Flag(...)`
/// shape spends minutes inside the multiline preprocessor) bails
/// after the configured budget instead of hanging the entire
/// `keyhog scan <repo>` run. The CLI orchestrator path runs scans
/// in parallel via rayon; a stuck worker would otherwise keep one
/// core pinned at 100% indefinitely.
///
/// Default unset (no timeout) preserves prior behavior. Recommend
/// `export KEYHOG_PER_CHUNK_TIMEOUT_MS=30000` (30 s) for production
/// scans where bounded latency matters more than scan completeness.
fn env_per_chunk_deadline() -> Option<std::time::Instant> {
    static MS: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    let ms = *MS.get_or_init(|| {
        std::env::var("KEYHOG_PER_CHUNK_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&v| v > 0)
    });
    ms.map(|ms| std::time::Instant::now() + std::time::Duration::from_millis(ms))
}

pub enum MlScoreResult<'a> {
    /// Score is final and the match can be pushed immediately.
    Final(f64),
    #[cfg(feature = "ml")]
    /// ML scoring is batched at the end of the scan.
    Pending {
        heuristic_conf: f64,
        code_context: crate::context::CodeContext,
        credential: std::borrow::Cow<'a, str>,
        ml_context: std::borrow::Cow<'a, str>,
    },
    /// Zero-sized placeholder that keeps the `'a` lifetime live when ML batch
    /// scoring is compiled out (lean / `--no-default-features` build). Never
    /// constructed - it exists solely so the type still carries `'a` without
    /// the `ml` feature, where only the borrowing `Pending` variant uses it.
    #[cfg(not(feature = "ml"))]
    #[doc(hidden)]
    _Lifetime(std::marker::PhantomData<&'a ()>),
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GpuInitPolicy {
    /// Honor KEYHOG_NO_GPU / CI auto-disable.
    FromEnvironment,
    /// Acquire a GPU backend when hardware is present, regardless of
    /// KEYHOG_NO_GPU. Used when the operator explicitly forces GPU.
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
    // Only the `gpu` build holds a concrete wgpu handle — its sole purpose
    // is to reach `dispatch_borrowed_batch`, which the trait object can't
    // express. Without the feature, the CUDA / wgpu drivers aren't linked
    // at all and `gpu_backend` is always None.
    #[cfg(feature = "gpu")]
    pub(crate) wgpu_backend: Option<Arc<vyre_driver_wgpu::WgpuBackend>>,
    pub(crate) gpu_literals: Option<Arc<Vec<Vec<u8>>>>,
    pub(crate) gpu_matcher: OnceLock<Option<vyre_libs::scan::GpuLiteralSet>>,
    /// On-GPU detection rule catalog (the megakernel `BatchDispatcher` path).
    /// Lazily built (or loaded from the on-disk cache) from `ac_map` on the
    /// first megakernel scan. The catalog always exists; `rule_count() == 0`
    /// means no pattern lowered, which `megakernel_catalog()` reports as `None`
    /// so the caller degrades loudly.
    #[cfg(feature = "gpu")]
    pub(crate) megakernel_catalog: OnceLock<megakernel::MegakernelCatalog>,
    pub(crate) ac_gpu_program: OnceLock<Option<vyre::Program>>,
    pub(crate) gpu_last_degrade_reason: std::sync::Mutex<Option<String>>,
    pub(crate) gpu_degrade_count: std::sync::atomic::AtomicU64,
    pub(crate) rule_pipeline: OnceLock<Option<vyre_libs::scan::RulePipeline>>,
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
    /// Per-`ac_map` regex byte upper bound for GPU hit-local validation. `None`
    /// means the detector regex is unbounded or unparsable by the AST bounder,
    /// so GPU validation keeps the full prepared-chunk oracle.
    #[cfg(feature = "gpu")]
    pub(crate) ac_match_upper_bounds: Vec<Option<usize>>,
    pub(crate) ac_map: Vec<CompiledPattern>,
    /// Confirmed-pass suffix gate: AC over ac_map patterns' required suffix
    /// literals (every match ends with one). `ac_suffix_gate[i]` are pattern
    /// i's literal ids; a triggered pattern whose suffix literals are all absent
    /// from the chunk cannot match and is skipped (see `extract_confirmed_patterns`).
    pub(crate) suffix_gate_ac: Option<AhoCorasick>,
    pub(crate) ac_suffix_gate: Vec<Vec<u32>>,
    pub(crate) prefix_propagation: CsrU32,
    pub(crate) fallback: Vec<(CompiledPattern, Vec<String>)>,
    pub(crate) companions: Vec<Vec<CompiledCompanion>>,
    pub(crate) detectors: Vec<DetectorSpec>,
    pub(crate) same_prefix_patterns: CsrU32,
    pub(crate) fallback_keyword_ac: Option<AhoCorasick>,
    pub(crate) fallback_keyword_to_patterns: CsrU32,
    pub(crate) fallback_always_active_indices: Vec<usize>,
    /// Combined-RegexSet prefilter over `fallback_always_active_indices`. When
    /// present, the per-chunk fallback scan runs one linear set pass instead of
    /// every always-active pattern's regex over the whole chunk. `None` falls
    /// back to running them all (recall-identical, just slower).
    pub(crate) fallback_always_active_prefilter: Option<fallback::AlwaysActiveFallbackPrefilter>,
    /// Shared-anchor localization index over the fallback set. When present,
    /// eligible fallback patterns are verified anchored at candidate positions
    /// from one shared Aho-Corasick pass instead of each walking the whole
    /// chunk; non-eligible patterns keep the whole-chunk path. `None` when no
    /// pattern is anchor-eligible. Recall-identical (see `fallback_anchor`).
    pub(crate) fallback_anchor_index: Option<fallback_anchor::FallbackAnchorIndex>,
    /// Per-scanner performance route tuning (HS vs RegexSet, anchor
    /// localization, prefilter truncation, decode focus, confirmed-suffix gate,
    /// …). Resolved from the `KEYHOG_*` env defaults; differential parity tests
    /// override one route on THIS scanner via [`CompiledScanner::tuning`] without
    /// touching any global state. See [`fallback::ScannerTuning`].
    pub(crate) tuning: fallback::ScannerTuning,
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
    /// Pre-interned `(detector_id, detector_name, service)` triple per
    /// hot-pattern slot, index-parallel with `simdsieve_prefilter::HOT_PATTERNS`
    /// / `HOT_PATTERN_NAMES`. The simdsieve fast path emits directly and used to
    /// re-hash the three `&'static str` metadata constants through the CHD
    /// interner on every hot hit; this caches the resolved `Arc<str>` once so
    /// each emission is three `Arc::clone`s (PERF-locality_intern-1). Byte-
    /// identical to `static_intern.lookup(HOT_PATTERN_*[idx])`.
    #[cfg(feature = "simdsieve")]
    pub(crate) hot_metadata_by_index: Vec<(Arc<str>, Arc<str>, Arc<str>)>,
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
    pub alphabet_screen: Option<crate::alphabet_filter::AlphabetScreen>,
    pub(crate) bigram_bloom: crate::bigram_bloom::BigramBloom,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<CompiledScanner>;
};
