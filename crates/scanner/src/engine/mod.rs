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

pub use vyre_libs::scan::LiteralMatch;

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
) -> std::result::Result<vyre_libs::scan::RulePipeline, vyre_libs::scan::RegexCompileError> {
    vyre_libs::scan::build_rule_pipeline_from_regex(patterns, "input", "hits", input_len)
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
) -> std::result::Result<vyre_libs::scan::RulePipeline, vyre_libs::scan::RegexCompileError> {
    let started = std::time::Instant::now();
    let Some(cache_dir) = gpu_matcher_cache_dir() else {
        return build_rule_pipeline(patterns, input_len);
    };
    let cache_key = format!("pipe-{}", pipeline_cache_key(patterns, input_len));

    // Try the cache FIRST so a warm start skips `build_rule_pipeline`
    // entirely. The previous flow always pre-compiled to keep typed
    // error semantics for vyre's infallible-closure
    // `cached_load_or_compile`, which made the cache pointless — the
    // compile already ran by the time we asked the cache anything.
    // Use vyre's `engine_cache_path` + manual load/save instead.
    // Task #94.
    if let Some(path) = vyre_libs::scan::engine_cache_path(&cache_dir, &cache_key) {
        if let Ok(bytes) = std::fs::read(&path) {
            match vyre_libs::scan::RulePipeline::from_bytes(&bytes) {
                Ok(pipeline) => {
                    tracing::debug!(
                        target: "keyhog::routing",
                        patterns = patterns.len(),
                        input_len,
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "RulePipeline cache hit — skipped compile"
                    );
                    return Ok(pipeline);
                }
                Err(_) => {
                    // Stale / corrupt: best-effort remove and fall
                    // through to recompile.
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    // Cache miss: pay the typed-fallible compile, then save for the
    // next call. Save failure is logged but never breaks the scan.
    let pipeline = build_rule_pipeline(patterns, input_len)?;
    if let Some(path) = vyre_libs::scan::engine_cache_path(&cache_dir, &cache_key) {
        if let Ok(bytes) = pipeline.to_bytes() {
            let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::write(&tmp, &bytes).is_ok() {
                if let Err(error) = std::fs::rename(&tmp, &path) {
                    tracing::debug!(
                        target: "keyhog::routing",
                        error = %error,
                        path = %path.display(),
                        "rule pipeline cache rename failed"
                    );
                    let _ = std::fs::remove_file(&tmp);
                }
            }
        }
    }
    tracing::debug!(
        target: "keyhog::routing",
        patterns = patterns.len(),
        input_len,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "RulePipeline cache miss — compiled and saved"
    );
    Ok(pipeline)
}

/// Maximum input buffer length the MegaScan `RulePipeline` is
/// pre-compiled for. Chosen to match the orchestrator's
/// `BATCH_BYTES_BUDGET` (256 MiB) so any normal coalesced batch fits
/// the pre-built pipeline without needing recompile-per-batch.
/// Batches larger than this fall back to the literal-set path.
pub const MEGASCAN_INPUT_LEN: usize = 256 * 1024 * 1024;

/// Output buffer cap for the AC GPU kernel, per shard dispatch.
/// Matches the implicit ~10 000-match ceiling the existing
/// `GpuLiteralSet` program declares; on overflow keyhog detects the
/// count > cap condition and falls back to CPU for the affected
/// shard (same protocol as the literal-set path). Per-buffer size
/// = `1_000_000 × 3 × 4 = 12 MiB` of VRAM per concurrent dispatch,
/// well within the wgpu storage-buffer limits on every device the
/// runtime activates.
pub const AC_GPU_MAX_MATCHES_PER_DISPATCH: u32 = 1_000_000;

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
/// Cached per-process GPU input constants — pre-packed LE byte streams
/// for the four pattern-shape inputs the GpuLiteralSet kernel reads on
/// every dispatch. Filled on first scan, borrowed thereafter.
pub struct GpuConstPacks {
    pub pattern_offsets: Vec<u8>,
    pub pattern_lengths: Vec<u8>,
    pub pattern_bytes: Vec<u8>,
    pub pattern_count: Vec<u8>,
}

/// Cached per-process AC-kernel input constants — pre-packed LE byte
/// streams for the four DFA-shape inputs the AC bounded-ranges kernel
/// reads on every dispatch. Separate from `GpuConstPacks` because the
/// AC kernel binds different fields (`dfa.transitions`,
/// `dfa.output_offsets`, `dfa.output_records`, `pattern_lengths`).
pub struct AcConstPacks {
    pub transitions: Vec<u8>,
    pub output_offsets: Vec<u8>,
    pub output_records: Vec<u8>,
    pub pattern_lengths: Vec<u8>,
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
    /// Active GPU backend, abstracted over the concrete driver crate.
    /// At `compile()` time we probe CUDA first (when the `cuda` feature
    /// is enabled and `libcuda.so` is loadable) and fall back to wgpu.
    /// CUDA bypasses the wgpu validation + naga IR + WGSL emit layers,
    /// runs native PTX through the CUDA driver, and overlaps shard
    /// dispatches on its own stream — typically 5-10x faster than wgpu
    /// on NVIDIA hardware. The wgpu path stays for AMD / Intel / Apple
    /// / non-NVIDIA hosts (no regression: same code as before).
    pub(crate) gpu_backend: Option<Arc<dyn vyre::VyreBackend>>,
    /// Concrete wgpu backend handle. `Some` only when wgpu is the
    /// active GPU backend (CUDA acquisition failed or `cuda` feature
    /// disabled). Held separately because the wgpu-batched dispatch
    /// path (`WgpuBackend::dispatch_borrowed_batch`) — one encoder,
    /// one submit, one poll for N shards — is wgpu-specific and not
    /// on the `VyreBackend` trait. CUDA uses parallel async dispatch
    /// through the trait method instead.
    pub(crate) wgpu_backend: Option<Arc<vyre_driver_wgpu::WgpuBackend>>,
    /// Literal prefixes supplied to Vyre's GPU Aho-Corasick engine.
    pub(crate) gpu_literals: Option<Arc<Vec<Vec<u8>>>>,
    pub(crate) gpu_matcher: OnceLock<Option<vyre_libs::scan::GpuLiteralSet>>,
    /// Pre-packed constant input bytes for every GPU literal-set dispatch.
    /// `(pattern_offsets, pattern_lengths, pattern_bytes, pattern_count)`
    /// all serialised to little-endian u32 byte streams once at first
    /// scan, then borrowed by every shard's bind-group input array.
    /// Before this cache, `scan_coalesced_gpu` called `pack_u32_slice`
    /// four times PER SCAN producing identical bytes — for a process
    /// scanning 10 k files that's 40 k throwaway Vec<u8> allocations
    /// when the data never changes after compile.
    pub(crate) gpu_const_packs: OnceLock<GpuConstPacks>,
    /// Same intent as `gpu_const_packs` but for the AC bounded-ranges
    /// kernel inputs (`KEYHOG_GPU_KERNEL=ac`).
    pub(crate) gpu_ac_const_packs: OnceLock<AcConstPacks>,
    /// Lazily-compiled Aho-Corasick bounded-ranges Program built from
    /// the SAME DFA the `gpu_matcher` holds. Two scan kernels share one
    /// DFA: `GpuLiteralSet` walks per-byte × per-pattern (O(N×L)/byte)
    /// and `classic_ac_bounded_ranges_program` walks per-byte using
    /// the AC transition table (O(L_max)/byte, ~1000× fewer per-byte
    /// ops for keyhog's pattern count). Selected at scan time via
    /// `KEYHOG_GPU_KERNEL=ac`. `None` once the OnceLock fires means
    /// no GPU matcher is available, same auto-degrade as `gpu_matcher`.
    pub(crate) ac_gpu_program: OnceLock<Option<vyre::Program>>,

    /// Frozen static-string interner built from detector metadata at
    /// scanner construction. Hands out shared `Arc<str>` for every
    /// `(detector_id, detector_name, service, source_type)` value
    /// without per-scan allocation. Lock-free on read so all rayon
    /// workers can consult it concurrently. See `static_intern.rs`.
    pub(crate) static_intern: Arc<crate::static_intern::StaticInterner>,
    /// Lazily-compiled regex-NFA pipeline for the MegaScan backend.
    /// `None` once the OnceLock fires means the regex compile failed
    /// (typically vyre's per-subgroup state cap or an unsupported
    /// regex feature) — MegaScan auto-degrades to the literal-set
    /// path when that happens.
    pub(crate) rule_pipeline: OnceLock<Option<vyre_libs::scan::RulePipeline>>,
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
        // Resolve the active GPU backend with the cascade
        //     CUDA (when `cuda` feature on + libcuda.so loadable)
        //     → wgpu (any-vendor cross-platform fallback)
        //     → None (auto-routes to SIMD/CPU).
        // CUDA bypasses the wgpu validation layers + naga IR + WGSL
        // text + driver shader compile; the path through CUDA driver
        // API + PTX is empirically 5-10× faster on NVIDIA hardware
        // and is the headline path. CUDA acquisition is opaque to
        // failures: if libcuda.so is missing or the driver refuses,
        // `acquire()` returns Err and we fall through to wgpu so
        // nothing regresses on non-CUDA hosts.
        let (gpu_literals, gpu_backend, wgpu_backend) =
            if crate::hw_probe::probe_hardware().gpu_available {
                let literals = build_gpu_literals(&state.ac_literals);
                let cuda_backend: Option<Arc<dyn vyre::VyreBackend>> = {
                    #[cfg(feature = "cuda")]
                    {
                        match vyre_driver_cuda::cuda_factory() {
                            Ok(boxed) => {
                                tracing::info!(
                                    target: "keyhog::routing",
                                    "CUDA backend acquired — bypassing wgpu/naga/WGSL path"
                                );
                                Some(Arc::from(boxed))
                            }
                            Err(error) => {
                                tracing::debug!(
                                    "CUDA backend unavailable, will try wgpu fallback: {error}"
                                );
                                None
                            }
                        }
                    }
                    #[cfg(not(feature = "cuda"))]
                    {
                        None
                    }
                };
                match cuda_backend {
                    Some(cuda) => (literals, Some(cuda), None),
                    None => match vyre_driver_wgpu::WgpuBackend::shared() {
                        Ok(wgpu) => {
                            let trait_obj: Arc<dyn vyre::VyreBackend> = wgpu.clone();
                            (literals, Some(trait_obj), Some(wgpu))
                        }
                        Err(_) => (literals, None, None),
                    },
                }
            } else {
                (None, None, None)
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
            // Mirrors `compiler::build_fallback_keyword_ac`'s
            // 4-char floor — see the rationale comment there. The
            // experimental 3-char floor measured a net F1 regression
            // on SecretBench-medium, so both checks stay at 4.
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

        // Pre-intern detector metadata strings into a CHD perfect
        // hash so per-scan `intern_metadata` calls hand out shared
        // `Arc<str>` without touching the global allocator. Built
        // once per scanner; lock-free on read.
        let static_intern_strings: Vec<&str> = detectors
            .iter()
            .flat_map(|d| [d.id.as_str(), d.name.as_str(), d.service.as_str()].into_iter())
            .collect();
        let static_intern = Arc::new(crate::static_intern::StaticInterner::from_detector_strings(
            static_intern_strings,
        ));

        Ok(Self {
            ac,
            gpu_backend,
            wgpu_backend,
            gpu_literals,
            gpu_matcher: OnceLock::new(),
            gpu_const_packs: OnceLock::new(),
            gpu_ac_const_packs: OnceLock::new(),
            ac_gpu_program: OnceLock::new(),

            rule_pipeline: OnceLock::new(),
            static_intern,
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
    pub fn gpu_matcher(&self) -> Option<&vyre_libs::scan::GpuLiteralSet> {
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
                // `vyre_libs::scan::cached_load_or_compile`. The
                // helper handles atomic-rename, stale-blob deletion,
                // and silent fall-through on cache-side I/O errors —
                // every behaviour the previous hand-rolled
                // load/save pair tried to match. We log compile cost
                // here so the operator can still see warm-vs-cold
                // start latency in `--verbose` output.
                let matcher =
                    vyre_libs::scan::cached_load_or_compile(&cache_dir, &cache_key, || {
                        vyre_libs::scan::GpuLiteralSet::compile(&literal_refs)
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

    /// Lazily build the Aho-Corasick bounded-ranges dispatch Program
    /// from the GpuLiteralSet's CompiledDfa. The two engines share the
    /// same DFA — only the dispatch Program (and therefore the
    /// per-byte algorithm) differs:
    ///
    /// * `gpu_matcher().program` — `build_literal_set_program`:
    ///   walks every pattern × every literal byte per haystack
    ///   position. `O(N × L) per byte`. Works for any pattern set
    ///   that fits the DFA budget.
    /// * `ac_gpu_program()` — `classic_ac_bounded_ranges_program`:
    ///   walks the AC transition table forward `L_max` bytes per
    ///   position, emits every pattern in the accepting state's
    ///   flat output_links. `O(L_max) per byte` regardless of N.
    ///
    /// Selected at scan time via `KEYHOG_GPU_KERNEL=ac`. Returns
    /// `None` when no GPU matcher is available; callers fall through
    /// to the literal-set path or non-GPU backend.
    ///
    /// Cap of `AC_GPU_MAX_MATCHES_PER_DISPATCH` triples per shard
    /// dispatch matches the existing literal-set output-buffer cap.
    /// Truncation (count > cap on readback) is handled by the same
    /// fall-back-to-CPU branch the literal-set path uses.
    pub fn ac_gpu_program(&self) -> Option<&vyre::Program> {
        self.ac_gpu_program
            .get_or_init(|| {
                let matcher = self.gpu_matcher()?;
                let pattern_count = matcher.pattern_lengths.len() as u32;
                // Pick the match-append strategy based on what the
                // active backend can actually lower. wgpu emits
                // `subgroup_ballot` + `subgroup_shuffle` natively
                // (gives ~32x atomic-contention reduction via
                // Innovation I.17). vyre-driver-cuda rejects the
                // subgroup form during canonical pre-emit lowering
                // ("variable `_vyre_match_leader` is referenced
                // before binding") so the CUDA path must use the
                // plain `append_match` variant for now. Either path
                // produces bit-identical match output; the difference
                // is purely atomic-coalescing strategy.
                let backend_id = self.gpu_backend.as_ref().map(|b| b.id()).unwrap_or("none");
                let use_subgroup_coalesce = backend_id != "cuda";
                let program = vyre_libs::scan::classic_ac::build_ac_bounded_ranges_program_ext(
                    &matcher.dfa,
                    pattern_count,
                    AC_GPU_MAX_MATCHES_PER_DISPATCH,
                    use_subgroup_coalesce,
                );
                tracing::debug!(
                    target: "keyhog::routing",
                    pattern_count,
                    state_count = matcher.dfa.state_count,
                    max_pattern_len = matcher.dfa.max_pattern_len,
                    backend = backend_id,
                    use_subgroup_coalesce,
                    "AC GPU dispatch Program built"
                );
                Some(program)
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
    pub fn rule_pipeline(&self) -> Option<&vyre_libs::scan::RulePipeline> {
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
                        // Demoted from `warn` to `debug` — the
                        // fallback to literal-set GPU dispatch is the
                        // designed degradation when vyre's byte-NFA
                        // frontend can't represent every pattern (e.g.
                        // lookaround in pattern 990 of the bundled
                        // detector corpus). The user can't fix it, and
                        // hitting this WARN once per `--backend mega-
                        // scan` invocation creates noise without
                        // signal. kimi-dogfood-3 #138.
                        tracing::debug!(
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

    /// Iterator over the FINAL regex source strings (post anchoring /
    /// group extraction / normalization) the scanner uses. Exposed
    /// for the sharded `RulePipeline` planner: callers need the same
    /// byte string the scanner runs against to bin patterns by
    /// compiled-NFA state count.
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

    /// Reset the cross-file fragment-reassembly cache.
    ///
    /// The cache accumulates fragments across every scan invocation on
    /// this scanner instance so a credential split across two files
    /// (`a.env` has `key=...`, `b.env` has the value) reassembles when
    /// the second file is scanned. That accumulation is intentional for
    /// a one-shot `keyhog scan /dir` run, but tests that reuse a scanner
    /// across independent fixtures see cross-fixture state leak — call
    /// this between fixtures to isolate them. Production callers
    /// generally do NOT need to call this; the cache lives for the scan
    /// process anyway.
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
        self.post_process_matches_inner(chunk, matches, deadline);
    }

    pub(crate) fn post_process_matches_inner(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
    ) {
        let pp_start = std::time::Instant::now();
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
                    // Decoded sub-chunks are post-process recursion;
                    // they're typically tiny (base64/hex/url payloads
                    // sliced out of the outer chunk). NEVER route them
                    // to the GPU literal-set: per-dispatch overhead
                    // (driver init + queue submit + sync) is 10-100 ms,
                    // and `KEYHOG_BACKEND=gpu` would otherwise force
                    // every decoded chunk through that path. On a
                    // 64 MiB chunk that decodes into 1 000 sub-chunks
                    // that's a 50-second tax — exactly the wall-clock
                    // delta keyhog used to show vs SIMD on messy
                    // corpora. Force a CPU backend here regardless of
                    // env override.
                    let decoded_backend = {
                        #[cfg(feature = "simd")]
                        {
                            crate::hw_probe::ScanBackend::SimdCpu
                        }
                        #[cfg(not(feature = "simd"))]
                        {
                            crate::hw_probe::ScanBackend::CpuFallback
                        }
                    };
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
        tracing::debug!(
            target: "keyhog::routing",
            chunk_bytes = chunk.data.len(),
            matches = matches.len(),
            elapsed_ms = pp_start.elapsed().as_millis() as u64,
            "post_process_matches_inner done",
        );
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

        let Some(assign_re) = crate::shared_regexes::ASSIGN_RE.as_ref() else {
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
                // Compute the trigger value's byte offset within chunk.data.
                // `line` borrows from chunk.data so pointer arithmetic gives
                // the line's offset; value_match.start() is offset within
                // `line`. Used below to give reassembled findings a REAL
                // source-file position instead of the synthetic
                // dummy_chunk offset (which used to read ~19 — the length
                // of the `reassembled_key = "` prefix). Synthetic offsets
                // broke the chunk-boundary recall invariant (proptest
                // gpu_proptest_invariants P3): identical credentials got
                // different offsets depending on whether the source was
                // scanned as one chunk or two, making the test see false
                // "drops". Real-source-offset removes that asymmetry.
                let fragment_value_offset = {
                    let line_offset =
                        line.as_ptr() as usize - chunk.data.as_ref().as_ptr() as usize;
                    line_offset + value_match.start()
                };
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

                    // Tiny synthesized chunk — NEVER dispatch through
                    // GPU even if `KEYHOG_BACKEND=gpu` is set; the
                    // per-dispatch overhead (~10-100 ms) is orders of
                    // magnitude larger than scanning ~50 bytes on the
                    // CPU. The previous flow leaked the env override
                    // into `select_backend_for_file` and turned a
                    // 64 MiB messy-corpus scan into ~60 s of dummy
                    // GPU launches.
                    let backend = {
                        #[cfg(feature = "simd")]
                        {
                            crate::hw_probe::ScanBackend::SimdCpu
                        }
                        #[cfg(not(feature = "simd"))]
                        {
                            crate::hw_probe::ScanBackend::CpuFallback
                        }
                    };
                    let mut reassembled_matches = self.scan_inner(&dummy_chunk, backend, deadline);
                    for m in &mut reassembled_matches {
                        m.detector_id = format!("{}:reassembled", m.detector_id).into();
                        // Point the finding to the trigger fragment's
                        // line AND byte offset in the source chunk.
                        // Previously offset was the synthetic position
                        // inside `"reassembled_key = \"…\""` (~19 bytes
                        // from dummy_chunk start), which broke the
                        // chunk-boundary recall invariant since the
                        // same credential got different synthetic
                        // offsets depending on chunk topology.
                        m.location.line = Some(fragment_line);
                        // kimi-engine audit: chunk metadata can carry
                        // `base_offset` near usize::MAX (custom sources
                        // synthesizing chunks). Unchecked addition would
                        // panic in debug / wrap in release; saturating
                        // pins to MAX which is a benign garbage offset
                        // (no legitimate file is 18 EB long) but does
                        // not panic mid-scan.
                        m.location.offset =
                            fragment_value_offset.saturating_add(chunk.metadata.base_offset);
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
                // kimi-engine audit: defensive bounds check. ac_map and
                // same_prefix_patterns SHOULD be the same length after
                // compilation, but if a future deserialization path
                // restores compiled state from disk with a mismatched
                // shape (or a bug in the compiler tears the invariant)
                // we'd panic on the indexed access. .get() turns that
                // into a benign skip — we lose the same-prefix expansion
                // for this pattern rather than crashing the scan.
                if let Some(siblings) = self.same_prefix_patterns.get(pat_idx) {
                    for &other_idx in siblings {
                        // Same defensive bound on the expanded write —
                        // a stale sibling index past the bitmask end
                        // would otherwise panic via bounds-checked
                        // slice index. We compute the bucket up front
                        // and silently skip out-of-range writes.
                        let bucket = other_idx / 64;
                        if let Some(slot) = expanded.get_mut(bucket) {
                            *slot |= 1u64 << (other_idx % 64);
                        }
                    }
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

            // `--scan-comments` opts the Comment context out of the
            // ML-blended confidence multiplier so a real credential in
            // a `// TODO: rotate this …` comment surfaces with the
            // same weight as one on a bare assignment line. TestCode
            // and Documentation contexts stay penalised regardless —
            // both produce orders-of-magnitude more EXAMPLE noise
            // than real leaks.
            let context_penalty_applies = match pending.code_context {
                crate::context::CodeContext::Comment => !self.config.scan_comments,
                crate::context::CodeContext::TestCode
                | crate::context::CodeContext::Documentation => true,
                _ => false,
            };
            if context_penalty_applies && final_score < 0.95 {
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
