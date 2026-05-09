//! Core scanning engine implementation.

mod backend;
mod boundary;
mod fallback;
mod fallback_entropy;
mod fallback_generic;
mod hot_patterns;
mod scan;
mod scan_filters;
mod scan_gpu;
pub mod segment_attribution;
mod windowed;

pub use windowed::{
    floor_char_boundary, line_number_for_offset, next_window_offset, record_window_match,
    window_chunk, window_end_offset,
};

use crate::compiler::*;
use crate::context::{self, CodeContext};
use crate::error::Result;
use crate::pipeline::*;
use crate::types::*;
use crate::unicode_hardening;
use aho_corasick::AhoCorasick;
#[cfg(feature = "entropy")]
use keyhog_core::MatchLocation;
use keyhog_core::{Chunk, DetectorSpec, RawMatch};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::OnceLock;

pub use vyre_libs::matching::LiteralMatch;

/// Compile a `RulePipeline` (vyre's regex multimatch path) for the
/// given detector regex sources, sized for `input_len` bytes. Uses
/// vyre's `regex_compile::build_rule_pipeline_from_regex` so each
/// pattern is parsed via `regex_syntax` (with `unicode(false)` /
/// `utf8(false)` — ASCII byte automaton) and lowered to the same
/// transition + epsilon tables `RulePipeline::scan` expects.
///
/// Returns `Err` when the combined NFA exceeds vyre's per-subgroup
/// state cap (`LANES * 32`), or when any pattern uses regex features
/// (Unicode classes, lookbehind/lookahead, backreferences) the
/// byte-NFA frontend can't represent. Caller decides whether to fall
/// back to the literal-set GPU dispatch (which always works but only
/// matches literals) or to skip MegaScan altogether for this corpus.
pub fn build_rule_pipeline(
    patterns: &[&str],
    input_len: u32,
) -> std::result::Result<
    vyre_libs::matching::RulePipeline,
    vyre_libs::matching::RegexCompileError,
> {
    vyre_libs::matching::build_rule_pipeline_from_regex(patterns, "input", "hits", input_len)
}

/// Persistent cache for `RulePipeline`. Mirrors the GpuLiteralSet
/// caching layer (same on-disk dir, same atomic-write protocol, same
/// SHA-256-of-inputs key). The two caches coexist so consumers that
/// run BOTH the literal-set and the regex pipeline (the planned
/// fast-path / regex-completion split) get cold-start speedup on each
/// without colliding cache files.
///
/// On-disk path: `~/.cache/keyhog/programs/pipe-<sha256>.bin`.
const PIPELINE_CACHE_VERSION: u32 = 1;

fn pipeline_cache_key(patterns: &[&str], input_len: u32) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(PIPELINE_CACHE_VERSION.to_le_bytes());
    h.update(input_len.to_le_bytes());
    h.update((patterns.len() as u32).to_le_bytes());
    for p in patterns {
        h.update((p.len() as u32).to_le_bytes());
        h.update(p.as_bytes());
    }
    let digest = h.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}

/// Compile-or-load a `RulePipeline` for the given regex set. First call
/// hits the on-disk cache; misses recompile and re-cache. Returns
/// `Err` when the regex compile itself fails (state-cap overflow or
/// unsupported regex syntax) — the caller is expected to log + fall
/// back to the literal-set GPU dispatch in that case.
///
/// The on-disk cache is keyed by the (patterns, input_len, vyre wire
/// version) tuple so a vyre IR bump or a detector change automatically
/// invalidates the cache instead of loading a stale pipeline.
pub fn rule_pipeline_cached(
    patterns: &[&str],
    input_len: u32,
) -> std::result::Result<
    vyre_libs::matching::RulePipeline,
    vyre_libs::matching::RegexCompileError,
> {
    let started = std::time::Instant::now();
    let Some(cache_dir) = gpu_matcher_cache_dir() else {
        return build_rule_pipeline(patterns, input_len);
    };
    // The vyre `cached_load_or_compile` API expects an infallible
    // builder closure (it has no way to bubble compile errors out).
    // We work around that by trying the regex compile UPFRONT — if
    // that succeeds, we know the cache builder will succeed too, so
    // hand it the same pipeline shape. If it fails, surface the
    // typed error to the caller.
    let pipe = build_rule_pipeline(patterns, input_len)?;
    let cache_key = format!("pipe-{}", pipeline_cache_key(patterns, input_len));
    // Cache lookup/store is best-effort: a stale or unwritable cache
    // is degraded behavior, not a correctness problem. We still hand
    // back the freshly-compiled pipeline above either way.
    let cached = vyre_libs::matching::cached_load_or_compile(&cache_dir, &cache_key, || pipe.clone());
    tracing::debug!(
        target: "keyhog::routing",
        patterns = patterns.len(),
        input_len,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "RulePipeline ready (warm cache or compiled)"
    );
    Ok(cached)
}

/// Maximum input buffer length the MegaScan `RulePipeline` is
/// pre-compiled for. Chosen to match the orchestrator's
/// `BATCH_BYTES_BUDGET` (256 MiB) so any normal coalesced batch fits
/// the pre-built pipeline without needing recompile-per-batch.
/// Batches larger than this fall back to the literal-set path.
pub const MEGASCAN_INPUT_LEN: usize = 256 * 1024 * 1024;

/// On-disk cache for `GpuLiteralSet`. The compiled matcher is keyed by a
/// SHA-256 of the literal set + the vyre wire version (which is bumped
/// whenever the IR layout changes), so bumping vyre to a new minor
/// version automatically invalidates the cache instead of silently
/// loading a stale matcher. Lives at `$XDG_CACHE_HOME/keyhog/programs/`
/// (typically `~/.cache/keyhog/programs/`).
const GPU_MATCHER_CACHE_VERSION: u32 = 1;

fn gpu_matcher_cache_dir() -> Option<std::path::PathBuf> {
    let dir = dirs::cache_dir()?.join("keyhog").join("programs");
    if !dir.exists() && std::fs::create_dir_all(&dir).is_err() {
        return None;
    }
    Some(dir)
}

fn gpu_matcher_cache_key(literals: &[&[u8]]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(GPU_MATCHER_CACHE_VERSION.to_le_bytes());
    h.update((literals.len() as u32).to_le_bytes());
    for lit in literals {
        h.update((lit.len() as u32).to_le_bytes());
        h.update(lit);
    }
    let digest = h.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}
pub enum MlScoreResult {
    /// Score is final and the match can be pushed immediately.
    Final(f64),
    #[cfg(feature = "ml")]
    /// ML scoring is deferred to a batch call at the end of the scan.
    Pending {
        heuristic_conf: f64,
        code_context: crate::context::CodeContext,
        credential: String,
        ml_context: String,
    },
}

pub struct CompiledScanner {
    pub(crate) fragment_cache: crate::fragment_cache::FragmentCache,
    pub(crate) ac: Option<AhoCorasick>,
    /// Persistent GPU backend for this scanner. `None` when no compatible
    /// adapter is available — keyhog auto-routes to SIMD/CPU in that case.
    pub(crate) wgpu_backend: Option<Arc<vyre_driver_wgpu::WgpuBackend>>,
    /// Literal prefixes supplied to Vyre's GPU Aho-Corasick engine.
    pub(crate) gpu_literals: Option<Arc<Vec<Vec<u8>>>>,
    pub(crate) gpu_matcher: OnceLock<Option<vyre_libs::matching::GpuLiteralSet>>,
    /// Lazily-compiled regex-NFA pipeline for the MegaScan backend.
    /// `None` once the OnceLock fires means the regex compile failed
    /// (typically vyre's per-subgroup state cap or an unsupported
    /// regex feature) — MegaScan auto-degrades to the literal-set
    /// path when that happens.
    pub(crate) rule_pipeline: OnceLock<Option<vyre_libs::matching::RulePipeline>>,
    pub(crate) ac_map: Vec<CompiledPattern>,
    pub(crate) prefix_propagation: Vec<Vec<usize>>,
    pub(crate) fallback: Vec<(CompiledPattern, Vec<String>)>,
    pub(crate) companions: Vec<Vec<CompiledCompanion>>,
    pub(crate) detectors: Vec<DetectorSpec>,
    pub(crate) same_prefix_patterns: Vec<Vec<usize>>,
    pub(crate) fallback_keyword_ac: Option<AhoCorasick>,
    pub(crate) fallback_keyword_to_patterns: Vec<Vec<usize>>,
    /// Pre-computed: index `i` is `true` iff fallback pattern `i`'s keywords
    /// are all <4 chars (so it can't be filtered by the keyword AC and must
    /// be considered active on every chunk). Computed once at scanner
    /// construction; avoids the `O(F × K)` walk the previous
    /// `populate_active_fallback` performed per chunk.
    pub(crate) fallback_always_active: Vec<bool>,
    #[cfg(feature = "simd")]
    pub(crate) simd_prefilter: Option<crate::simd::backend::HsScanner>,
    /// HS pattern ID → original ac_map indices.
    #[cfg(feature = "simd")]
    pub(crate) hs_index_map: Vec<Vec<usize>>,
    #[cfg(feature = "simdsieve")]
    pub(crate) simdsieve_prefilter: crate::simdsieve_prefilter::SimdPrefilter,
    pub config: ScannerConfig,
    pub alphabet_screen: Option<crate::alphabet_filter::AlphabetScreen>,
    /// Layer-0.5 bigram bloom — built once from the literal prefix set at
    /// `compile()` time. A chunk whose bigrams have ZERO overlap with any
    /// detector literal cannot possibly match; we skip the entire scan
    /// pipeline for it. Strictly cheaper than `AlphabetMask::from_bytes`
    /// because the bloom is a pre-built lookup, not per-chunk computation.
    pub(crate) bigram_bloom: crate::bigram_bloom::BigramBloom,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<CompiledScanner>;
};

impl CompiledScanner {
    /// Compile all detector specs into a single scanner.
    #[must_use = "the scanner is expensive to compile — use it for scanning"]
    pub fn compile(detectors: Vec<DetectorSpec>) -> Result<Self> {
        let state = build_compile_state(&detectors)?;
        let ac = build_ac_pattern_set(&state.ac_literals)?;
        // GPU is unconditional in the build; runtime probe decides whether to
        // actually use it. `gpu_available` is set by hw_probe based on adapter
        // detection (excluding software renderers like llvmpipe/lavapipe).
        let (gpu_literals, wgpu_backend) = if crate::hw_probe::probe_hardware().gpu_available {
            // Use the process-wide shared backend so keyhog's CLI ↔
            // library callers share one wgpu device + pipeline cache
            // instead of paying adapter-enumeration cost on every
            // `compile()`. Falls back to None on GPU init failure.
            (
                build_gpu_literals(&state.ac_literals),
                vyre_driver_wgpu::WgpuBackend::shared().ok(),
            )
        } else {
            (None, None)
        };
        let prefix_propagation = build_prefix_propagation(&state.ac_literals);
        let same_prefix_patterns = build_same_prefix_patterns(&state.ac_literals);
        let (fallback_keyword_ac, fallback_keyword_to_patterns) =
            build_fallback_keyword_ac(&state.fallback);
        // Precompute the per-pattern "always-active" bitmap so the per-chunk
        // hot path avoids walking every pattern's keyword list. See the
        // doc comment on the field for rationale.
        let fallback_always_active: Vec<bool> = state
            .fallback
            .iter()
            .map(|(_, keywords)| !keywords.iter().any(|k| k.len() >= 4))
            .collect();

        log_quality_warnings(&state.quality_warnings);

        #[cfg(feature = "simdsieve")]
        let simdsieve_prefilter = crate::simdsieve_prefilter::SimdPrefilter::new();

        #[cfg(feature = "simd")]
        let (simd_prefilter, hs_index_map) =
            backend::build_simd_scanner(&state.ac_map, &state.fallback)
                .map(|(s, m)| (Some(s), m))
                .unwrap_or((None, Vec::new()));

        let mut alphabet_targets = state.ac_literals.clone();
        for (_, keywords) in &state.fallback {
            alphabet_targets.extend(keywords.clone());
        }
        let alphabet_screen = if alphabet_targets.is_empty() {
            None
        } else {
            Some(crate::alphabet_filter::AlphabetScreen::new(
                &alphabet_targets,
            ))
        };

        let bigram_bloom =
            crate::bigram_bloom::BigramBloom::from_literal_prefixes(&alphabet_targets);
        tracing::debug!(
            popcount = bigram_bloom.popcount(),
            "bigram bloom built (4096 bits, lower popcount = stronger filter)"
        );

        Ok(Self {
            ac,
            wgpu_backend,
            gpu_literals,
            gpu_matcher: OnceLock::new(),
            rule_pipeline: OnceLock::new(),
            ac_map: state.ac_map,
            prefix_propagation,
            fallback: state.fallback,
            companions: state.companions,
            detectors,
            same_prefix_patterns,
            fallback_keyword_ac,
            fallback_keyword_to_patterns,
            fallback_always_active,
            #[cfg(feature = "simd")]
            simd_prefilter,
            #[cfg(feature = "simd")]
            hs_index_map,
            #[cfg(feature = "simdsieve")]
            simdsieve_prefilter,
            config: ScannerConfig::default(),
            alphabet_screen,
            bigram_bloom,
            fragment_cache: crate::fragment_cache::FragmentCache::new(1000),
        })
    }

    /// Apply a custom configuration to the compiled scanner.
    pub fn with_config(mut self, config: ScannerConfig) -> Self {
        self.config = config;
        self
    }

    /// Lazily compile the GPU literal-set on first call. Returns `None`
    /// when no compatible adapter was detected at probe time.
    ///
    /// Persists the compiled matcher to `~/.cache/keyhog/programs/<hash>.bin`
    /// using the new `GpuLiteralSet::to_bytes/from_bytes` (vyre 0.6+).
    /// On a cache hit the matcher is loaded from disk and the GPU
    /// recompile is skipped entirely — biggest cold-start win on
    /// `keyhog scan` / `scan-system` runs that re-launch repeatedly.
    /// Cache misses (no file, version-mismatch, corrupt blob) silently
    /// recompile and re-cache.
    pub fn gpu_matcher(&self) -> Option<&vyre_libs::matching::GpuLiteralSet> {
        self.gpu_matcher
            .get_or_init(|| {
                let Some(literals) = &self.gpu_literals else {
                    return None;
                };
                let literal_refs: Vec<&[u8]> = literals.iter().map(|v| v.as_slice()).collect();
                let cache_dir = gpu_matcher_cache_dir()?;
                let cache_key = format!("lit-{}", gpu_matcher_cache_key(&literal_refs));
                let started = std::time::Instant::now();
                // One-line lego-block cache wiring courtesy of
                // `vyre_libs::matching::cached_load_or_compile`. The
                // helper handles atomic-rename, stale-blob deletion,
                // and silent fall-through on cache-side I/O errors —
                // every behaviour the previous hand-rolled
                // load/save pair tried to match. We log compile cost
                // here so the operator can still see warm-vs-cold
                // start latency in `--verbose` output.
                let matcher =
                    vyre_libs::matching::cached_load_or_compile(&cache_dir, &cache_key, || {
                        vyre_libs::matching::GpuLiteralSet::compile(&literal_refs)
                    });
                tracing::debug!(
                    target: "keyhog::routing",
                    patterns = literal_refs.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "GpuLiteralSet ready (warm cache or compiled)"
                );
                Some(matcher)
            })
            .as_ref()
    }

    /// Lazily compile the regex-NFA `RulePipeline` on first call.
    /// Returns `None` once the OnceLock has fired when the regex
    /// compile failed — typically because the combined NFA exceeds
    /// vyre's per-subgroup state cap (`LANES * 32`) or because one
    /// of the detector regexes uses a feature the byte-NFA frontend
    /// can't represent (Unicode classes, lookaround, backrefs).
    /// Callers should fall back to the literal-set GPU dispatch on
    /// `None`.
    ///
    /// Pipeline is sized for [`MEGASCAN_INPUT_LEN`] bytes; batches
    /// larger than that must take a different path. The orchestrator
    /// caps batches at 256 MiB which is the chosen size, so this
    /// matches normal scan flow.
    pub fn rule_pipeline(&self) -> Option<&vyre_libs::matching::RulePipeline> {
        self.rule_pipeline
            .get_or_init(|| {
                let pattern_strs: Vec<&str> = self
                    .ac_map
                    .iter()
                    .map(|p| p.regex.as_str())
                    .chain(self.fallback.iter().map(|(p, _)| p.regex.as_str()))
                    .collect();
                if pattern_strs.is_empty() {
                    return None;
                }
                let started = std::time::Instant::now();
                match rule_pipeline_cached(&pattern_strs, MEGASCAN_INPUT_LEN as u32) {
                    Ok(pipe) => {
                        tracing::info!(
                            target: "keyhog::routing",
                            patterns = pattern_strs.len(),
                            input_len = MEGASCAN_INPUT_LEN,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "MegaScan RulePipeline compiled"
                        );
                        Some(pipe)
                    }
                    Err(error) => {
                        tracing::warn!(
                            patterns = pattern_strs.len(),
                            error = %format!("{error:?}"),
                            "MegaScan RulePipeline compile failed — falling back to literal-set GPU dispatch. \
                             Common causes: regex set exceeds vyre's per-subgroup state cap, or one or more \
                             patterns use Unicode classes / lookaround / backrefs that the byte-NFA frontend \
                             can't represent."
                        );
                        None
                    }
                }
            })
            .as_ref()
    }

    /// Number of loaded detectors.
    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    /// Total number of patterns (AC + fallback).
    pub fn pattern_count(&self) -> usize {
        self.ac_map.len() + self.fallback.len()
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

    /// Return the steady-state backend label used for startup reporting.
    #[must_use]
    pub fn preferred_backend_label(&self) -> &'static str {
        self.select_backend_for_file(0).label()
    }

    /// Warm backend resources that are initialized lazily during scanning.
    pub fn warm_backend(&self, backend: crate::hw_probe::ScanBackend) -> bool {
        match backend {
            crate::hw_probe::ScanBackend::Gpu => self.gpu_matcher().is_some(),
            crate::hw_probe::ScanBackend::MegaScan => {
                // Warm the regex-NFA pipeline AND the literal-set
                // matcher: when the regex compile fails (state-cap
                // overflow), MegaScan dispatch silently degrades to
                // the literal-set path, so both need to be ready.
                let _ = self.rule_pipeline();
                self.gpu_matcher().is_some()
            }
            crate::hw_probe::ScanBackend::SimdCpu | crate::hw_probe::ScanBackend::CpuFallback => {
                true
            }
        }
    }

    /// Scan a chunk of text and return all raw credential matches.
    pub fn scan(&self, chunk: &Chunk) -> Vec<RawMatch> {
        self.scan_with_deadline(chunk, None)
    }

    /// Scan a chunk using a caller-selected backend.
    pub fn scan_with_backend(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<RawMatch> {
        self.scan_with_deadline_and_backend(chunk, None, Some(backend))
    }

    /// Scan multiple chunks using a caller-selected backend.
    pub fn scan_chunks_with_backend(
        &self,
        chunks: &[Chunk],
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<Vec<RawMatch>> {
        self.scan_chunks_with_backend_internal(chunks, backend)
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
                return Vec::new();
            }
        }

        if let Some(screen) = &self.alphabet_screen {
            if !screen.screen(chunk.data.as_bytes()) {
                return Vec::new();
            }
        }

        // Layer 0.5: bigram bloom. Skips chunks whose 2-byte windows have
        // ZERO overlap with any detector literal prefix. Empirically <1% FP
        // on real source corpora; concentrated wins on minified/binary/
        // lock files. Only run for chunks larger than ~64 bytes — for tiny
        // strings the windows() iteration cost approaches the bloom cost.
        if chunk.data.len() >= 64 && !self.bigram_bloom.maybe_overlaps(chunk.data.as_bytes()) {
            return Vec::new();
        }

        // simdsieve quick-screen: for inputs >100 KB, the 50 GB/s SIMD prefilter
        // could short-circuit chunks with no plausible secret-prefix bigrams.
        // We DO NOT gate the pipeline on this signal yet — the prefilter only
        // knows about the 8 hardcoded HOT_PATTERNS, so a negative result is
        // only meaningful for scanners whose detector set is a subset of those
        // patterns (which is rare: test scanners and custom-detector users
        // load arbitrary literals). Wiring this into a real early-return
        // requires teaching simdsieve about the compiled scanner's full
        // literal prefix set; tracked as legendary-2026-04-26 perf-win #11.
        #[cfg(feature = "simdsieve")]
        if chunk.data.len() > 100_000 {
            let (_likely_hit, _confidence) =
                self.simdsieve_prefilter.quick_screen(chunk.data.as_bytes());
        }

        let selected_backend =
            backend.unwrap_or_else(|| self.select_backend_for_file(chunk.data.len() as u64));
        // Per-chunk routing visibility — only logged at trace level so
        // production scans don't pay the format cost, but `RUST_LOG=keyhog=trace`
        // gives a per-chunk audit trail of which backend ran.
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

    pub(crate) fn post_process_matches(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
    ) {
        self.scan_cross_chunk_fragments(chunk, matches, deadline);

        #[cfg(feature = "decode")]
        if chunk.data.len() <= self.config.max_decode_bytes {
            // Dedup keys reuse the existing `Arc<str>` from `RawMatch` instead
            // of cloning to `String`. For 50+ pre-existing matches per chunk
            // this saves ~10-30 µs of allocator pressure per call.
            let mut seen: HashSet<(Arc<str>, Arc<str>)> = matches
                .iter()
                .map(|m| (Arc::clone(&m.detector_id), Arc::clone(&m.credential)))
                .collect();
            for decoded_chunk in crate::decode::decode_chunk(
                chunk,
                self.config.max_decode_depth,
                self.config.validate_decode,
                deadline,
                self.alphabet_screen.as_ref(),
            ) {
                // kimi-wave1 finding 5.LOW: a single decoded chunk that
                // exceeds `max_decode_bytes` slips past the outer guard
                // (which only checked the *input* chunk size). Skip
                // anything that grew past the configured ceiling — the
                // input was already a decode bomb if we got here.
                if decoded_chunk.data.len() > self.config.max_decode_bytes {
                    tracing::debug!(
                        path = ?chunk.metadata.path,
                        decoded_len = decoded_chunk.data.len(),
                        ceiling = self.config.max_decode_bytes,
                        "decoded chunk exceeds max_decode_bytes; skipping"
                    );
                    continue;
                }
                let decoded_matches = if decoded_chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
                    self.scan_windowed(&decoded_chunk, deadline)
                } else {
                    let decoded_backend =
                        self.select_backend_for_file(decoded_chunk.data.len() as u64);
                    self.scan_inner(&decoded_chunk, decoded_backend, deadline)
                };
                for m in decoded_matches {
                    let key = (Arc::clone(&m.detector_id), Arc::clone(&m.credential));
                    if seen.insert(key) {
                        matches.push(m);
                    }
                }
            }
        }
    }

    fn scan_cross_chunk_fragments(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
    ) {
        if !Self::has_fragment_assignment_syntax(chunk.data.as_bytes()) {
            return;
        }

        static ASSIGN_RE: std::sync::LazyLock<Option<regex::Regex>> =
            std::sync::LazyLock::new(|| {
                regex::Regex::new(
                    r#"(?i)([a-z0-9_-]{2,32})\s*[:=]\s*["'`]([a-zA-Z0-9/+=_-]{4,})["'`](?:;|,)?$"#,
                )
                .ok()
            });
        let Some(assign_re) = ASSIGN_RE.as_ref() else {
            return;
        };

        for (line_idx, line) in chunk.data.lines().enumerate() {
            if let Some(caps) = assign_re.captures(line) {
                let Some(var_name_match) = caps.get(1) else {
                    continue;
                };
                let Some(value_match) = caps.get(2) else {
                    continue;
                };

                let fragment_line = line_idx + 1;
                let fragment = crate::fragment_cache::SecretFragment {
                    prefix: crate::multiline::extract_prefix(var_name_match.as_str()),
                    var_name: var_name_match.as_str().to_string(),
                    value: zeroize::Zeroizing::new(value_match.as_str().to_string()),
                    line: fragment_line,
                    path: chunk
                        .metadata
                        .path
                        .as_ref()
                        .map(|p| std::sync::Arc::from(p.as_str())),
                };

                let candidates = self.fragment_cache.record_and_reassemble(fragment);
                for candidate in candidates {
                    // `candidate` is `Zeroizing<String>` (kimi-wave1 fix).
                    let entropy = crate::pipeline::match_entropy(candidate.as_bytes());
                    if entropy < 3.0 || candidate.len() < 16 {
                        continue;
                    }

                    let mut dummy_data = String::with_capacity(candidate.len() + 24);
                    dummy_data.push_str("reassembled_key = \"");
                    dummy_data.push_str(candidate.as_str());
                    dummy_data.push('"');
                    let dummy_chunk = Chunk {
                        data: dummy_data.into(),
                        metadata: chunk.metadata.clone(),
                    };

                    let backend = self.select_backend_for_file(dummy_chunk.data.len() as u64);
                    let mut reassembled_matches = self.scan_inner(&dummy_chunk, backend, deadline);
                    for m in &mut reassembled_matches {
                        m.detector_id = format!("{}:reassembled", m.detector_id).into();
                        // FIX: Point the finding to the line where the trigger fragment was found.
                        // Better than pointing to line 1 of a virtual chunk.
                        m.location.line = Some(fragment_line);
                    }
                    matches.append(&mut reassembled_matches);
                    // Zeroized automatically on drop (SensitiveString)
                }
            }
        }
    }

    fn has_fragment_assignment_syntax(data: &[u8]) -> bool {
        let has_assignment =
            memchr::memchr(b'=', data).is_some() || memchr::memchr(b':', data).is_some();
        let has_quote = memchr::memchr(b'"', data).is_some()
            || memchr::memchr(b'\'', data).is_some()
            || memchr::memchr(b'`', data).is_some();
        has_assignment && has_quote
    }

    fn expand_triggered_patterns(&self, triggered_patterns: &[u64]) -> Vec<u64> {
        // Propagate ONLY via `same_prefix_patterns`: when AC matches a
        // literal prefix shared by patterns X and Y, both X and Y need
        // to be evaluated since they're different regexes that happen
        // to share the same fixed prefix.
        //
        // The previous flow ALSO propagated via `detector_to_patterns`,
        // expanding to every other pattern of the same detector. That
        // was wasted work: each pattern is in `ac_map` *because* it has
        // a literal AC prefix, and if Y's prefix was not matched in
        // this chunk, Y's regex (which starts with that prefix) can't
        // match either. The expansion forced full-text regex passes on
        // patterns that were guaranteed to return no matches — the
        // dominant cost of the per-detector regex pass on chunks that
        // trigger multiple AC patterns of multi-pattern detectors.
        let mut expanded = triggered_patterns.to_vec();
        for (word_idx, &word) in triggered_patterns.iter().enumerate() {
            if word == 0 {
                continue;
            }
            let mut bits = word;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                let pat_idx = word_idx * 64 + bit;
                if pat_idx >= self.ac_map.len() {
                    break;
                }
                for &other_idx in &self.same_prefix_patterns[pat_idx] {
                    expanded[other_idx / 64] |= 1 << (other_idx % 64);
                }
                bits &= bits - 1; // clear lowest set bit
            }
        }
        expanded
    }

    #[allow(clippy::too_many_arguments)]
    fn extract_confirmed_patterns(
        &self,
        confirmed_patterns: &[usize],
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        for &pat_idx in confirmed_patterns {
            if let Some(deadline) = deadline {
                if std::time::Instant::now() > deadline {
                    break;
                }
            }
            let entry = if pat_idx < self.ac_map.len() {
                &self.ac_map[pat_idx]
            } else {
                let fallback_idx = pat_idx - self.ac_map.len();
                if fallback_idx >= self.fallback.len() {
                    continue;
                }
                &self.fallback[fallback_idx].0
            };
            self.extract_matches(
                entry,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                0,
                0,
                deadline,
            );
        }
    }

    #[cfg(feature = "ml")]
    fn apply_ml_batch_scores(&self, scan_state: &mut ScanState) {
        if scan_state.ml_pending.is_empty() {
            return;
        }

        if !self.config.ml_enabled {
            let pending = scan_state.ml_pending.drain(..).collect::<Vec<_>>();
            for p in pending {
                let mut raw_match = p.raw_match;
                raw_match.confidence = Some(p.heuristic_conf);
                scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
            }
            return;
        }

        // Borrow rather than clone — `ml_pending` is alive for the duration
        // of the call, so `&str` references stay valid through ML scoring.
        // On a wide scan with hundreds of pending matches this drops 2N
        // owned-string allocations per batch.
        let candidates: Vec<(&str, &str)> = scan_state
            .ml_pending
            .iter()
            .map(|pending| (pending.credential.as_str(), pending.ml_context.as_str()))
            .collect();

        let scores = crate::gpu::batch_ml_inference(&candidates, &self.config);
        let pending_matches: Vec<_> = scan_state.ml_pending.drain(..).collect();
        for (pending, ml_conf) in pending_matches.into_iter().zip(scores) {
            let mut final_score = (crate::types::ML_WEIGHT * ml_conf)
                + (crate::types::HEURISTIC_WEIGHT * pending.heuristic_conf);
            final_score = final_score.max(pending.heuristic_conf).max(ml_conf);

            if matches!(
                pending.code_context,
                crate::context::CodeContext::TestCode
                    | crate::context::CodeContext::Documentation
                    | crate::context::CodeContext::Comment
            ) && final_score < 0.95
            {
                final_score *= pending.code_context.confidence_multiplier();
            }

            let final_score =
                crate::confidence::apply_post_ml_penalties(final_score, &pending.credential);
            let final_score = crate::confidence::apply_path_confidence_penalties(
                final_score,
                pending.raw_match.location.file_path.as_deref(),
            );
            let final_score = if let Some(floor) =
                crate::confidence::known_prefix_confidence_floor(&pending.credential)
            {
                final_score.max(floor)
            } else {
                final_score
            };

            // Bayesian calibration multiplier (Tier-B #4). No-op when no
            // calibration cache exists or the detector has zero recorded
            // observations beyond the Beta(1,1) prior. Detectors with a
            // long clean track get amplified; chronic FP-emitters muted.
            let final_score = crate::confidence::apply_calibration_multiplier(
                final_score,
                &pending.raw_match.detector_id,
            );

            if !pending.code_context.should_hard_suppress(final_score) {
                let mut raw_match = pending.raw_match;
                raw_match.confidence = Some(final_score);
                scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
            }
        }
    }
}
