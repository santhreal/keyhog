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
mod extract;
pub(crate) mod fallback;
mod fallback_anchor;
mod fallback_entropy;
mod fallback_entropy_helpers;
mod fallback_generic;
pub(crate) mod fallback_truncate;
mod gpu_cache;
mod gpu_forced;
mod gpu_lazy;
#[cfg(feature = "gpu")]
pub(crate) mod megakernel;
#[cfg(feature = "gpu")]
mod megakernel_dispatch;
mod hot_patterns;
mod process;
pub(crate) mod profile;
mod rule_pipeline;
mod scan;
mod scan_filters;
mod scan_inner_profile;
mod scan_postprocess;
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
pub use fallback::{
    fallback_gate_stats_dump, set_decode_focus, set_fallback_anchor_mode, set_fallback_hs,
    set_fallback_homoglyph_gate, set_fallback_prefix_gate, set_fallback_reverse,
    set_homoglyph_ascii_skip, set_prefilter_truncate,
};
pub use rule_pipeline::{
    build_rule_pipeline, megascan_input_len, rule_pipeline_cached, AC_GPU_MAX_MATCHES_PER_DISPATCH,
    MEGASCAN_INPUT_LEN, MEGASCAN_INPUT_LEN_DEFAULT,
};
pub use profile::{dump as profile_dump, reset as profile_reset};
pub use scan_inner_profile::scan_inner_profile_dump;
pub use scan_postprocess::decode_profile_dump;
pub use scan_postprocess::set_confirmed_suffix_gate;
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

/// Compressed-sparse-row (CSR) index table: a flattened replacement for a
/// `Vec<Vec<usize>>` whose rows are pattern/literal indices.
///
/// The detector-side index maps (`prefix_propagation`, `same_prefix_patterns`,
/// `fallback_keyword_to_patterns`, and the simd `hs_index_map`) are each
/// indexed parallel to the ~1000+ AC literals / fallback patterns. Stored as
/// `Vec<Vec<usize>>` that is ~1000+ separate heap allocations per table, each
/// inner `Vec` carrying a 24-byte (ptr+len+cap) header plus capacity slack -
/// even for the overwhelmingly common empty or single-element row. That
/// fragments the heap, forces pointer-chasing on the hot lookup path (every
/// row a separate cacheline), and wastes 8-byte `usize` where the values are
/// corpus-bounded indices that fit in `u32`.
///
/// CSR collapses each table to exactly two allocations: `data` holds every
/// row concatenated, and `offsets` (length `n + 1`) records where each row
/// starts, so `row(i) == &data[offsets[i]..offsets[i + 1]]`. Empty rows cost
/// zero data bytes instead of a header, element width halves to `u32`, and
/// lookups are contiguous. Build it once from the existing
/// `Vec<Vec<usize>>`-producing builders via `From` (or directly with
/// `from_rows`); reads go through [`CsrU32::get`], mirroring the slice/`Vec`
/// API the old field type exposed.
#[derive(Clone, Debug, Default)]
pub(crate) struct CsrU32 {
    /// All rows concatenated, in row order.
    data: Vec<u32>,
    /// `offsets[i]..offsets[i + 1]` is the slice of `data` for row `i`.
    /// Always non-empty once built: a table of `n` rows has `n + 1` offsets.
    offsets: Vec<u32>,
}

impl CsrU32 {
    /// Build a CSR table from per-row index lists in a single pass.
    ///
    /// Accepts any iterator of rows so the existing builders can feed their
    /// `Vec<Vec<usize>>` (or borrowed slices) straight in without an
    /// intermediate allocation. Values are narrowed to `u32`; a corpus index
    /// can never exceed the pattern count, which is far below `u32::MAX`.
    pub(crate) fn from_rows<R, I>(rows: R) -> Self
    where
        R: IntoIterator<Item = I>,
        I: IntoIterator<Item = usize>,
    {
        let mut data = Vec::new();
        let mut offsets = vec![0u32];
        for row in rows {
            for v in row {
                data.push(v as u32);
            }
            offsets.push(data.len() as u32);
        }
        Self { data, offsets }
    }

    /// Row `i` as a contiguous slice, or `None` when `i` is out of range.
    /// Replaces `Vec::get(i) -> Option<&Vec<usize>>` on the hot lookup path.
    #[inline]
    pub(crate) fn get(&self, i: usize) -> Option<&[u32]> {
        let start = *self.offsets.get(i)? as usize;
        let end = *self.offsets.get(i + 1)? as usize;
        Some(&self.data[start..end])
    }
}

impl From<Vec<Vec<usize>>> for CsrU32 {
    fn from(rows: Vec<Vec<usize>>) -> Self {
        Self::from_rows(rows)
    }
}

impl std::ops::Index<usize> for CsrU32 {
    type Output = [u32];

    #[inline]
    fn index(&self, i: usize) -> &[u32] {
        let start = self.offsets[i] as usize;
        let end = self.offsets[i + 1] as usize;
        &self.data[start..end]
    }
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

impl CompiledScanner {
    /// Whether a SIMD (Hyperscan/Vectorscan) prefilter is compiled in and live.
    ///
    /// The GPU phase-1 paths reroute a batch through the SIMD coalesced scan
    /// when the GPU prefix output is too dense for phase 2. That reroute only
    /// exists when the `simd` feature is on; in `--no-default-features`
    /// (portable / macOS no-system-libs) builds the `simd_prefilter` field is
    /// `#[cfg]`-compiled out entirely, so there is nothing to reroute into and
    /// the answer is always `false`. This accessor keeps the reroute guards
    /// compiling in every feature combination without scattering
    /// `#[cfg(feature = "simd")]` across each call site.
    ///
    /// Compiled only under `gpu`: its SOLE consumer is
    /// `degraded_backend_after_gpu_failure` on the GPU dispatch path, so a
    /// no-`gpu` build never asks the question. Gating it here keeps the
    /// no-`gpu` profiles warning-clean (Law 11) without changing any answer.
    /// `gpu` implies `simd` at the feature level (see keyhog-scanner Cargo.toml
    /// — the megakernel reuses the SIMD phase-2 tail), so the `simd_prefilter`
    /// field is always present here; the runtime `is_some()` still reflects
    /// whether the Hyperscan database actually built.
    #[cfg(feature = "gpu")]
    #[inline]
    pub(crate) fn has_simd_prefilter(&self) -> bool {
        self.simd_prefilter.is_some()
    }

    /// Number of loaded detectors.
    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    /// Pre-interned `(detector_id, detector_name, service)` triple for the
    /// detector at `detector_index`. Three `Arc::clone`s, zero hashing — the
    /// hot-path replacement for three `ScanState::intern_metadata` calls on
    /// frozen detector metadata (PERF-locality_intern-1). Returns byte-for-byte
    /// the same `Arc<str>` values `static_intern.lookup(...)` would, because
    /// they ARE the same arena entries, so emitted findings are unchanged.
    #[inline]
    pub(crate) fn interned_detector_metadata(
        &self,
        detector_index: usize,
    ) -> (Arc<str>, Arc<str>, Arc<str>) {
        let (id, name, service) = &self.metadata_by_index[detector_index];
        (Arc::clone(id), Arc::clone(name), Arc::clone(service))
    }

    /// Total number of patterns (AC + fallback).
    pub fn pattern_count(&self) -> usize {
        self.ac_map.len() + self.fallback.len()
    }

    /// Diagnostic: `(fallback_total, always_active, always_active_eligible)` —
    /// how much the shared-anchor index shrinks the RegexSet prefilter. The
    /// prefilter cost scales with `always_active - always_active_eligible`.
    pub fn fallback_anchor_stats(&self) -> (usize, usize, usize) {
        let total = self.fallback.len();
        let always_active = self.fallback_always_active_indices.len();
        let aae = self.fallback_anchor_index.as_ref().map_or(0, |idx| {
            self.fallback_always_active_indices
                .iter()
                .filter(|&&i| idx.is_always_active_eligible(i))
                .count()
        });
        (total, always_active, aae)
    }

    /// Diagnostic: `(regex_source, keywords)` for every keyword-gated fallback
    /// pattern, in `fallback` order. These are the no-literal-prefix detectors
    /// that `scan_fallback_patterns` runs over the whole chunk once their
    /// keyword fires. Used by anchor-localization analysis to classify which
    /// carry a regex-required literal that can drive a windowed (rather than
    /// whole-chunk) scan. Diagnostic surface only — not part of the scan path.
    pub fn fallback_pattern_diagnostics(&self) -> Vec<(String, Vec<String>)> {
        self.fallback
            .iter()
            .map(|(p, kw)| (p.regex.as_str().to_string(), kw.clone()))
            .collect()
    }

    /// Eagerly compile every pattern's regex, in parallel, up front.
    ///
    /// Patterns compile lazily on first use (see [`crate::types::LazyRegex`]),
    /// which makes a one-shot CLI scan start in milliseconds instead of
    /// paying ~450ms-2.3s to build the whole corpus. For a LONG-lived or
    /// LARGE scan - the daemon, `watch`, `scan-system`, or a big repo where a
    /// detector fires across thousands of files - it's better to pay the
    /// compile once, in parallel, before the hot loop rather than stalling
    /// the first file that touches each detector. Callers on those paths
    /// should `warm()` after building the scanner.
    ///
    /// Idempotent and cheap to repeat: an already-compiled pattern is a
    /// `OnceLock` hit. Also the correct setup for a per-scan perf benchmark,
    /// which means to measure match throughput, not one-time compilation.
    pub fn warm(&self) {
        use rayon::prelude::*;
        // Warm the lazy regex transition caches in parallel so the first real
        // source batch does not serialize DFA first-touch under worker load.
        const WARM_SAMPLE: &str = concat!(
            "int main(void){ char *buf = malloc(4096); for(size_t i=0;i<len;i++){ ",
            "config.timeout_ms = 30000; user_id=0x1f3b9c; const KEY = \"abcDEF0123456789\"; ",
            "https://example.org/api/v2?token=eyJhbGciOi&id=550e8400-e29b-41d4-a716; ",
            "base64=QUtJQUlPU0ZPRE5ON0VYQU1QTEU= sha=da39a3ee5e6b4b0d3255bfef95601890; ",
            "snake_case_name camelCaseName SCREAMING_CASE path/to/file.rs node_modules ",
            "} /* comment */ // trailing\n\t<xml attr='v'>text</xml> {\"json\":true,\"n\":42}"
        );
        self.ac_map.par_iter().for_each(|p| {
            let _ = p.regex.get().find(WARM_SAMPLE);
        });
        self.fallback.par_iter().for_each(|(p, _)| {
            let _ = p.regex.get().find(WARM_SAMPLE);
        });
        crate::shared_regexes::warm_runtime_regexes();
        fallback_generic::warm_generic_assignment_runtime();
        crate::multiline::warm_runtime_regexes();
        crate::checksum::warm_runtime_regexes();
    }

    /// Iterator over the FINAL regex source strings (post anchoring /
    /// group extraction / normalization) the scanner uses.
    pub fn pattern_regex_strs(&self) -> Vec<&str> {
        let mut out = Vec::with_capacity(self.ac_map.len() + self.fallback.len());
        out.extend(self.ac_map.iter().map(|p| p.regex.as_str()));
        out.extend(self.fallback.iter().map(|(p, _)| p.regex.as_str()));
        out
    }

    /// Return the preferred backend for a file of the given size.
    #[must_use]
    pub fn select_backend_for_file(&self, file_size: u64) -> crate::hw_probe::ScanBackend {
        crate::hw_probe::select_backend(
            crate::hw_probe::probe_hardware(),
            file_size,
            self.pattern_count(),
        )
    }

    /// Identifier of the GPU backend acquired at compile time, or
    /// None if scanning routes to CPU/SIMD only. Mirrors
    /// `VyreBackend::id()` which returns "cuda", "wgpu", or the
    /// driver-defined name. The startup banner uses this so the
    /// operator can tell at a glance whether they got CUDA (the
    /// headline 5-10x faster path on NVIDIA hardware) or the WGPU
    /// fallback, rather than just "Gpu" which collapses both.
    #[must_use]
    pub fn gpu_backend_label(&self) -> Option<&'static str> {
        self.gpu_backend.as_ref().map(|b| b.id())
    }

    /// Most recent concrete GPU runtime-degrade reason for this compiled
    /// scanner, if one has occurred. Used by health probes to emit
    /// machine-readable failure causes without scraping stderr.
    pub fn last_gpu_degrade_reason(&self) -> Option<String> {
        self.gpu_last_degrade_reason
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Return the steady-state backend label used for startup reporting.
    #[must_use]
    pub fn preferred_backend_label(&self) -> &'static str {
        self.select_backend_for_file(0).label()
    }

    /// Warm backend resources that are initialized lazily during scanning.
    pub fn warm_backend(&self, backend: crate::hw_probe::ScanBackend) -> bool {
        let ready = match backend {
            crate::hw_probe::ScanBackend::Gpu => self.gpu_stack_usable(),
            crate::hw_probe::ScanBackend::MegaScan => {
                let pipeline_ready = self.rule_pipeline().is_some();
                let stack_ready = self.gpu_stack_usable();
                if !pipeline_ready && stack_ready {
                    gpu_forced::deny_silent_megascan_degrade(
                        "regex pipeline compile rejected the detector set",
                    );
                }
                pipeline_ready && stack_ready
            }
            crate::hw_probe::ScanBackend::SimdCpu | crate::hw_probe::ScanBackend::CpuFallback => {
                true
            }
        };
        if !ready {
            gpu_forced::deny_silent_gpu_degrade(self, backend);
        }
        ready
    }

    /// Scan a chunk of text and return all raw credential matches.
    pub fn scan(&self, chunk: &Chunk) -> Vec<RawMatch> {
        self.scan_with_deadline(chunk, env_per_chunk_deadline())
    }

    /// Scan a chunk using a caller-selected backend.
    pub fn scan_with_backend(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<RawMatch> {
        self.scan_with_deadline_and_backend(chunk, env_per_chunk_deadline(), Some(backend))
    }

    /// Scan multiple chunks using a caller-selected backend.
    pub fn scan_chunks_with_backend(
        &self,
        chunks: &[Chunk],
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<Vec<RawMatch>> {
        gpu_forced::deny_silent_gpu_degrade(self, backend);
        profile::add_bytes(chunks.iter().map(|c| c.data.len() as u64).sum());
        profile::add_files(chunks.len() as u64);
        self.scan_chunks_with_backend_internal(chunks, backend)
    }

    /// Reset the cross-file fragment-reassembly cache.
    pub fn clear_fragment_cache(&self) {
        self.fragment_cache.clear();
    }

    /// Scan a chunk of text against all compiled detectors.
    pub fn scan_with_deadline(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        self.scan_with_deadline_and_backend(chunk, deadline, None)
    }

    pub fn scan_with_deadline_and_backend(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
        backend: Option<crate::hw_probe::ScanBackend>,
    ) -> Vec<RawMatch> {
        if let Some(path) = chunk.metadata.path.as_deref() {
            let filename = path.rsplit(['/', '\\']).next().unwrap_or(path);
            if filename == ".keyhog"
                || filename == ".keyhogignore"
                || path.split(['/', '\\']).any(|c| c == "detectors")
            {
                crate::telemetry::record_file_skipped();
                return Vec::new();
            }
        }

        // Direct-match prefilters: skip chunks that carry none of any
        // detector's literal bytes (`AlphabetScreen`) or bigrams (bloom). A
        // FULLY-ENCODED secret (e.g. `data = "<base64-of-ghp_…>"`) carries none
        // of those - its plaintext prefix only appears AFTER decoding - so the
        // prefilters would drop it before decode-through could recover it,
        // silently defeating the decode-through feature on the encoded-only
        // case. When the prefilter rejects but decode is enabled AND the chunk
        // carries a long base64/hex run, fall through to a DECODE-ONLY pass
        // instead of skipping. Bounded: only encoded-looking rejected chunks
        // pay the decode cost, so normal traffic keeps the fast skip.
        let alphabet_ok = self
            .alphabet_screen
            .as_ref()
            .map_or(true, |screen| screen.screen(chunk.data.as_bytes()));
        let bigram_ok =
            chunk.data.len() < 64 || self.bigram_bloom.maybe_overlaps(chunk.data.as_bytes());
        if !(alphabet_ok && bigram_ok) {
            #[cfg(feature = "decode")]
            if self.config.max_decode_depth > 0
                && chunk.data.len() <= self.config.max_decode_bytes
                && crate::decode::has_decodable_payload(chunk.data.as_bytes())
            {
                // Direct scan is skipped (the outer bytes match nothing); only
                // the decoded sub-chunks are scanned, inside post_process.
                let mut matches = Vec::new();
                self.post_process_matches(chunk, &mut matches, deadline);
                return matches;
            }
            crate::telemetry::record_file_skipped();
            return Vec::new();
        }

        let selected_backend =
            backend.unwrap_or_else(|| self.select_backend_for_file(chunk.data.len() as u64));
        gpu_forced::deny_silent_gpu_degrade(self, selected_backend);
        tracing::trace!(
            target: "keyhog::routing",
            backend = selected_backend.label(),
            chunk_bytes = chunk.data.len(),
            source_type = chunk.metadata.source_type.as_str(),
            "scan dispatch"
        );
        let mut matches = if chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
            self.scan_windowed(chunk, deadline)
        } else {
            self.scan_inner(chunk, selected_backend, deadline)
        };

        self.post_process_matches(chunk, &mut matches, deadline);

        matches
    }
}
