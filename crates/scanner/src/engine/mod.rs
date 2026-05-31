//! Core scanning engine implementation.

mod backend;
mod backend_dispatch;
mod backend_pattern_hits;
mod backend_prepared;
mod backend_triggered;
pub mod boundary;
mod compile;
mod extract;
mod fallback;
mod fallback_entropy;
mod fallback_entropy_helpers;
mod fallback_generic;
mod gpu_ac_phase1;
mod gpu_cache;
mod gpu_coalesce;
pub mod gpu_decode_scan;
mod gpu_dispatch;
mod gpu_forced;
mod gpu_lazy;
mod gpu_literal_phase1;
mod gpu_megascan;
mod gpu_phase2;
pub(crate) mod gpu_postprocess;
pub mod gpu_program_fusion;
pub mod gpu_regex_dfa;
mod gpu_scan_wrappers;
mod hot_patterns;
mod process;
mod rule_pipeline;
mod scan;
mod scan_filters;
mod scan_postprocess;
pub mod segment_attribution;
mod windowed;

// `build_simd_scanner` only exists under the `simd` (Hyperscan) feature; its
// sole call site in compile.rs is `#[cfg(feature = "simd")]` too. Gate the
// import to match, or non-simd builds (the `portable` feature used for the
// macOS/Windows/musl release assets) fail with E0432.
#[cfg(feature = "simd")]
pub(crate) use backend_prepared::build_simd_scanner;
pub(crate) use backend_prepared::PreparedChunk;
pub use gpu_cache::{AcConstPacks, GpuConstPacks};
pub use gpu_coalesce::coalesce_chunks;
pub use gpu_regex_dfa::{build_regex_dfa, RegexDfaError};
pub use gpu_scan_wrappers::GpuPhase1Output;
pub use rule_pipeline::{
    build_rule_pipeline, megascan_input_len, rule_pipeline_cached, AC_GPU_MAX_MATCHES_PER_DISPATCH,
    MEGASCAN_INPUT_LEN, MEGASCAN_INPUT_LEN_DEFAULT,
};
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
/// `from_rows`); reads go through [`CsrU32::get`] / [`CsrU32::row`] /
/// [`CsrU32::len`], mirroring the slice/`Vec` API the old field type exposed.
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

    /// Number of rows (parallel to the literal/pattern table it indexes).
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    /// True when the table has no rows.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Row `i` as a contiguous slice, or `None` when `i` is out of range.
    /// Replaces `Vec::get(i) -> Option<&Vec<usize>>` on the hot lookup path.
    #[inline]
    pub(crate) fn get(&self, i: usize) -> Option<&[u32]> {
        let start = *self.offsets.get(i)? as usize;
        let end = *self.offsets.get(i + 1)? as usize;
        Some(&self.data[start..end])
    }

    /// Row `i` as a slice, returning an empty slice when out of range.
    /// Convenience for call sites that already bounds-checked against
    /// [`CsrU32::len`] and previously wrote `table[i].as_slice()`.
    #[inline]
    pub(crate) fn row(&self, i: usize) -> &[u32] {
        self.get(i).unwrap_or(&[])
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
    pub(crate) gpu_const_packs: OnceLock<GpuConstPacks>,
    pub(crate) gpu_ac_const_packs: OnceLock<AcConstPacks>,
    pub(crate) ac_gpu_program: OnceLock<Option<vyre::Program>>,
    pub(crate) rule_pipeline: OnceLock<Option<vyre_libs::scan::RulePipeline>>,
    /// Fused AC + rule pipeline program (single GPU dispatch instead of two).
    /// Lazily built on first access via `fused_program()`.
    pub(crate) fused_program: OnceLock<Option<vyre::Program>>,
    /// Fused decode→scan programs for base64/hex GPU decode.
    /// Lazily built on first access.
    pub(crate) fused_decode_programs: OnceLock<Option<gpu_decode_scan::FusedDecodeScanPrograms>>,
    pub(crate) static_intern: Arc<crate::static_intern::StaticInterner>,
    pub(crate) ac_map: Vec<CompiledPattern>,
    pub(crate) prefix_propagation: Vec<Vec<usize>>,
    pub(crate) fallback: Vec<(CompiledPattern, Vec<String>)>,
    pub(crate) companions: Vec<Vec<CompiledCompanion>>,
    pub(crate) detectors: Vec<DetectorSpec>,
    pub(crate) same_prefix_patterns: Vec<Vec<usize>>,
    pub(crate) fallback_keyword_ac: Option<AhoCorasick>,
    pub(crate) fallback_keyword_to_patterns: Vec<Vec<usize>>,
    pub(crate) fallback_always_active_indices: Vec<usize>,
    #[cfg(feature = "simd")]
    pub(crate) simd_prefilter: Option<crate::simd::backend::HsScanner>,
    #[cfg(feature = "simd")]
    pub(crate) hs_index_map: Vec<Vec<usize>>,
    /// Precise-regex validator per hot-pattern slot (index-parallel with
    /// `simdsieve_prefilter::HOT_PATTERNS`). The hot fast-path runs each
    /// literal-prefix candidate through these before emitting so it can never
    /// surface a token the detector's own regex rejects (the length floor
    /// alone let `ghp_…_…`/`xoxp-123-456-789-abc` through). `None` for the one
    /// slot with no canonical detector (square).
    #[cfg(feature = "simdsieve")]
    pub(crate) hot_pattern_validators: Vec<Option<regex::Regex>>,
    pub config: ScannerConfig,
    pub alphabet_screen: Option<crate::alphabet_filter::AlphabetScreen>,
    pub(crate) bigram_bloom: crate::bigram_bloom::BigramBloom,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<CompiledScanner>;
};

impl CompiledScanner {
    /// Number of loaded detectors.
    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    /// Total number of patterns (AC + fallback).
    pub fn pattern_count(&self) -> usize {
        self.ac_map.len() + self.fallback.len()
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
        self.ac_map.par_iter().for_each(|p| {
            let _ = p.regex.get();
        });
        self.fallback.par_iter().for_each(|(p, _)| {
            let _ = p.regex.get();
        });
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

        if let Some(screen) = &self.alphabet_screen {
            if !screen.screen(chunk.data.as_bytes()) {
                crate::telemetry::record_file_skipped();
                return Vec::new();
            }
        }

        if chunk.data.len() >= 64 && !self.bigram_bloom.maybe_overlaps(chunk.data.as_bytes()) {
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
