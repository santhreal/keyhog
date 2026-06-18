use crate::args::ScanArgs;
use anyhow::{Context, Result};
use keyhog_core::{load_detectors, validate_detector, DetectorSpec, QualityIssue};
use keyhog_scanner::ScannerConfig;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

const DETECTOR_CACHE_VERSION: u32 = 3;

#[derive(Serialize, Deserialize)]
struct DetectorCacheFile {
    version: u32,
    source_fingerprint: String,
    detectors: Vec<DetectorSpec>,
}

/// Hard ceiling on the parallel thread count. Above this, thread
/// creation overhead + scheduler contention dominates any throughput
/// gain on CPU-bound work. Matches the cap the rayon docs recommend
/// for general-purpose pools and protects against `--threads 9999999`
/// misconfiguration that would either OOM-on-spawn or thrash the
/// scheduler on a 4-core box.
/// Hard ceiling on the worker thread count. Requested values above this are
/// clamped (and logged) by [`sanitise_thread_count`]; spawning thousands of
/// threads thrashes the OS scheduler without speeding the scan up.
pub(crate) const MAX_THREADS_CAP: usize = 256;

/// Canonical default for `--ml-threshold` (`ScanArgs::ml_threshold`). Single
/// source of truth for the flag's declared default: the clap `default_value`
/// literal in `args/scan.rs` stringifies this same value, and
/// [`build_scanner_config`] compares the parsed flag against it to decide
/// whether the operator actually moved the knob. An unset flag (value equal to
/// this default) must leave the canonical confidence floor untouched, so the
/// fix for a dead `--ml-threshold` does not silently change default behaviour.
pub(crate) const ML_THRESHOLD_DEFAULT: f64 = 0.5;

/// Default chunk batch size for the fused filesystem read+scan pipeline.
pub(crate) const FUSED_BATCH_DEFAULT: usize = 32;

/// Default bounded-channel depth for fused filesystem batches.
pub(crate) fn fused_depth_default(worker_threads: usize) -> usize {
    worker_threads
        .saturating_add(3)
        .saturating_div(4)
        .clamp(2, 8)
}

pub(crate) fn parse_backend_override(
    raw: Option<&str>,
) -> Result<Option<keyhog_scanner::ScanBackend>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
        return Ok(None);
    }
    keyhog_scanner::hw_probe::parse_backend_str(trimmed)
        .map(Some)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "invalid --backend value {:?}. Supported values: auto, gpu, mega-scan, megascan, simd, cpu.",
                raw
            )
        })
}

pub(crate) fn backend_override_label(backend: Option<keyhog_scanner::ScanBackend>) -> &'static str {
    backend.map_or("auto", keyhog_scanner::ScanBackend::label)
}

pub(crate) fn gpu_runtime_policy_from_args(
    args: &ScanArgs,
) -> keyhog_scanner::gpu::GpuRuntimePolicy {
    if args.require_gpu {
        keyhog_scanner::gpu::GpuRuntimePolicy::Required
    } else if args.no_gpu {
        keyhog_scanner::gpu::GpuRuntimePolicy::Disabled
    } else {
        keyhog_scanner::gpu::GpuRuntimePolicy::Auto
    }
}

pub(crate) fn configure_threads(threads: Option<usize>, physical_cores: usize) {
    // Resolution order: --threads / [scan].threads > physical core count.
    // Physical (not logical) is the right default for CPU-bound regex: SMT /
    // Hyperthreading siblings share execution units, so 2x the threads yields
    // ~1.1x the throughput while doubling cache pressure.
    //
    // Each source is sanitised through `sanitise_thread_count`, which:
    //   * rejects 0 (rayon would silently use its own default - confusing)
    //   * caps at `MAX_THREADS_CAP` (avoids spawn failures + scheduler thrash)
    // Both paths log a warning so an operator who fat-fingered the value
    // sees what was actually used.
    let (n, source) = if let Some(t) = threads {
        (
            sanitise_thread_count(t, physical_cores, "cli-arg"),
            "cli-arg",
        )
    } else {
        (physical_cores.max(1), "physical-cores")
    };

    let builder = rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .stack_size(8 * 1024 * 1024)
        // Cross-OS thread name so external profilers (perf, dtrace,
        // Activity Monitor, htop) can group keyhog workers separately
        // from the calling process. Previously macOS-only.
        .thread_name(|i| format!("keyhog-worker-{i}"));

    if let Err(error) = builder.build_global() {
        tracing::warn!(
            requested_threads = n,
            source,
            "failed to configure rayon thread pool: {error}"
        );
    } else {
        tracing::info!(
            threads = n,
            source,
            physical_cores,
            "rayon thread pool configured"
        );
    }
}

pub(crate) fn configure_hyperscan_cache_dir(cache_dir: Option<PathBuf>) -> Result<()> {
    if let Some(path) = cache_dir.as_ref() {
        if !path.is_absolute() {
            anyhow::bail!(
                "Hyperscan cache dir '{}' must be absolute. Fix: pass an absolute path under \
                 your home directory or the per-user keyhog temp cache root.",
                path.display()
            );
        }
    }

    #[cfg(feature = "simd")]
    {
        if let Some(path) = cache_dir.as_ref() {
            keyhog_scanner::validate_hyperscan_cache_dir(path).map_err(|error| {
                anyhow::anyhow!("{error}. Configure with --cache-dir or [system].cache_dir")
            })?;
        }
        keyhog_scanner::set_hyperscan_cache_dir(cache_dir);
    }

    #[cfg(not(feature = "simd"))]
    {
        if cache_dir.is_some() {
            anyhow::bail!(
                "--cache-dir / [system].cache_dir requires a keyhog build with the simd \
                 feature; this binary has no Hyperscan cache to configure"
            );
        }
    }

    Ok(())
}

/// Clamp a user-supplied thread count to a sane range. Logs a
/// warning when the value was outside the accepted bounds so an
/// operator who passed `--threads 0` or `--threads 999999` sees what
/// the scanner actually used.
fn sanitise_thread_count(requested: usize, physical_cores: usize, source: &'static str) -> usize {
    let safe_default = physical_cores.max(1);
    if requested == 0 {
        eprintln!(
            "keyhog: invalid {source} thread count 0; expected an integer >= 1; using {safe_default}"
        );
        tracing::warn!(
            source,
            requested = 0,
            using = safe_default,
            "thread count of 0 is not meaningful; falling back to physical-cores"
        );
        return safe_default;
    }
    if requested > MAX_THREADS_CAP {
        eprintln!(
            "keyhog: {source} thread count {requested} exceeds cap {MAX_THREADS_CAP}; using {MAX_THREADS_CAP}"
        );
        tracing::warn!(
            source,
            requested,
            cap = MAX_THREADS_CAP,
            "requested thread count exceeds cap; clamping"
        );
        return MAX_THREADS_CAP;
    }
    requested
}

pub(crate) fn auto_discover_detectors(path: &Path) -> Result<PathBuf> {
    if path != Path::new("detectors") {
        return Ok(path.to_path_buf());
    }

    if path == Path::new("detectors") && !path.exists() {
        let mut default_dirs: Vec<Option<PathBuf>> = vec![
            dirs::home_dir().map(|h| h.join(".keyhog/detectors")),
            dirs::data_dir().map(|d| d.join("keyhog/detectors")),
            dirs::data_local_dir().map(|d| d.join("keyhog/detectors")),
        ];
        if cfg!(unix) {
            default_dirs.push(Some(PathBuf::from("/usr/share/keyhog/detectors")));
            default_dirs.push(Some(PathBuf::from("/usr/local/share/keyhog/detectors")));
        }
        default_dirs.push(
            std::env::current_exe()
                .ok() // LAW10: optional env/cwd probe; absent => None (intended config/probe), recall-irrelevant
                .and_then(|p| p.parent().map(|p| p.join("detectors"))),
        );
        for dir in default_dirs.into_iter().flatten() {
            if dir.exists() && dir.is_dir() {
                tracing::info!(detectors_dir = %dir.display(), "auto-detected detectors directory");
                return Ok(dir);
            }
        }
    }
    Ok(path.to_path_buf())
}

pub(crate) fn load_detectors_with_cache(path: &Path) -> Result<Vec<DetectorSpec>> {
    validate_detector_path_for_scan(path)?;
    if path.exists() && path.is_dir() {
        // The parse cache lives in the user's XDG cache dir, NOT inside the
        // detectors directory. A system install puts detectors under a
        // root-owned, read-only tree (e.g. /opt/keyhog/detectors,
        // /usr/share/keyhog/detectors); writing `.keyhog-cache.json` there
        // failed with `Permission denied` on EVERY run, spamming two WARN
        // lines and silently re-parsing each time. Keying the cache by the
        // source dir keeps distinct detector directories from colliding;
        // The CLI parse cache fingerprints the source TOML filenames and
        // contents, so removed/renamed/edited detectors cannot leave stale
        // detectors live just because no remaining file is newer than cache.
        let cache_path = detector_cache_path(path);
        if let Some(cache_path) = &cache_path {
            let loaded = load_detectors_from_dir_with_cache(path, cache_path)
                .context("loading detectors from directory with parse cache")?;
            require_non_empty_detectors(&loaded, path)?;
            return Ok(loaded);
        }
        let loaded = load_detectors(path)?;
        require_non_empty_detectors(&loaded, path)?;
        return Ok(loaded);
    }
    load_detectors_embedded_or_fail(path)
}

fn load_detectors_from_dir_with_cache(
    source_dir: &Path,
    cache_path: &Path,
) -> Result<Vec<DetectorSpec>> {
    if let Some(cached) = load_detector_cache(cache_path, source_dir) {
        return Ok(cached);
    }

    let loaded = load_detectors(source_dir).map_err(anyhow::Error::from)?;
    if loaded.is_empty() {
        return Ok(loaded);
    }
    let source_fingerprint = match detector_source_fingerprint(source_dir) {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            tracing::warn!(
                source_dir = %source_dir.display(),
                %error,
                "detector source changed after load; parse cache not written"
            );
            return Ok(loaded);
        }
    };
    if let Err(error) = save_detector_cache(&loaded, cache_path, source_fingerprint) {
        tracing::debug!(
            cache_path = %cache_path.display(),
            %error,
            "detector parse cache not written; re-parsing TOML on the next run"
        );
    }
    Ok(loaded)
}

fn save_detector_cache(
    detectors: &[DetectorSpec],
    cache_path: &Path,
    source_fingerprint: String,
) -> std::io::Result<()> {
    for detector in detectors {
        let issues = validate_detector(detector);
        if issues
            .iter()
            .any(|issue| matches!(issue, QualityIssue::Error(_)))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "refusing to cache invalid detector '{}'. Fix: repair the detector before writing the cache",
                    detector.id
                ),
            ));
        }
    }

    let json = serde_json::to_vec(&DetectorCacheFile {
        version: DETECTOR_CACHE_VERSION,
        source_fingerprint,
        detectors: detectors.to_vec(),
    })?;
    let parent = cache_path.parent().unwrap_or_else(|| Path::new(".")); // LAW10: cache path with no parent => current dir fallback before create_dir_all; cache write only, scan reparses source on failure
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    std::io::Write::write_all(&mut tmp, &json)?;
    tmp.as_file().sync_all()?;
    tmp.persist(cache_path).map_err(|e| e.error)?;
    Ok(())
}

fn load_detector_cache(cache_path: &Path, source_dir: &Path) -> Option<Vec<DetectorSpec>> {
    let source_fingerprint = match detector_source_fingerprint(source_dir) {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            tracing::warn!(
                source_dir = %source_dir.display(),
                %error,
                "cannot fingerprint detector source directory; ignoring detector cache and re-parsing TOML"
            );
            return None;
        }
    };

    let data = match std::fs::read(cache_path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::warn!(
                "failed to read detector cache {}: {}",
                cache_path.display(),
                error
            );
            return None;
        }
    };
    let cache: DetectorCacheFile = match serde_json::from_slice(&data) {
        Ok(cache) => cache,
        Err(error) => {
            tracing::warn!(
                "failed to parse detector cache {}: {}",
                cache_path.display(),
                error
            );
            return None;
        }
    };
    if cache.version != DETECTOR_CACHE_VERSION {
        return None;
    }
    if cache.source_fingerprint != source_fingerprint {
        return None;
    }

    let mut validated = Vec::with_capacity(cache.detectors.len());
    for spec in cache.detectors {
        let issues = validate_detector(&spec);
        if issues
            .iter()
            .any(|issue| matches!(issue, QualityIssue::Error(_)))
        {
            tracing::warn!(
                "cached detector '{}' failed quality gate; discarding the entire cache",
                spec.id
            );
            return None;
        }
        validated.push(spec);
    }

    if validated.is_empty() {
        tracing::warn!("detector cache is empty after validation, re-parsing detector TOML");
        return None;
    }

    Some(validated)
}

fn detector_source_fingerprint(source_dir: &Path) -> std::io::Result<String> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(source_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.extension().is_some_and(|ext| ext == "toml") {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let bytes = std::fs::read(&path)?;
        entries.push((name, *blake3::hash(&bytes).as_bytes()));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = blake3::Hasher::new();
    for (name, hash) in entries {
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(&hash);
        hasher.update(b"\n");
    }
    Ok(keyhog_core::hex_encode(hasher.finalize().as_bytes()))
}

/// Path to the detector parse cache in the user's XDG cache dir, keyed by the
/// source directory so multiple `--detectors` trees don't collide. Returns
/// `None` when no cache dir is resolvable (cache simply disabled). The
/// `.json` is created on first successful parse and revalidated against the
/// source TOMLs' mtimes by the CLI parse-cache loader.
fn detector_cache_path(source_dir: &Path) -> Option<std::path::PathBuf> {
    use std::hash::{Hash, Hasher};
    let canonical = std::fs::canonicalize(source_dir).unwrap_or_else(|_| source_dir.to_path_buf()); // LAW10: canonicalize failure => original path (best-effort normalization); recall-safe
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    canonical.hash(&mut hasher);
    // Version-scope the key: the embedded/default corpus shape can change
    // across keyhog versions, so a stale cache from an old binary is never
    // reused by a new one.
    env!("CARGO_PKG_VERSION").hash(&mut hasher);
    let key = hasher.finish();
    Some(
        dirs::cache_dir()?
            .join("keyhog")
            .join(format!("detectors-{key:016x}.json")),
    )
}

/// Load detectors without writing or reading the on-disk
/// `.keyhog-cache.json`. Used by `--lockdown` to avoid touching disk.
/// Falls through to the embedded TOML corpus when no detectors dir
/// exists, matching `load_detectors_with_cache`'s behaviour.
pub(crate) fn load_detectors_no_cache(path: &Path) -> Result<Vec<DetectorSpec>> {
    validate_detector_path_for_scan(path)?;
    if path.exists() && path.is_dir() {
        let loaded = load_detectors(path).map_err(anyhow::Error::from)?;
        require_non_empty_detectors(&loaded, path)?;
        return Ok(loaded);
    }
    load_detectors_embedded_or_fail(path)
}

/// Hard-fail when detector loading produces zero specs. The
/// `load_detectors` path returns `Ok(Vec::new())` for an empty
/// directory, a directory full of malformed TOMLs that all get
/// quality-gate rejected, or a typo'd `--detectors` path that
/// happens to be a directory. Without this gate the scan runs
/// against zero patterns, finds nothing, and exits SUCCESS - the
/// user (or their CI) reads "no findings" and assumes the code
/// is clean. That's the definition of a silent-data-loss bug.
///
/// `pub(crate)` so subcommands (`watch`, `scan-system`, `explain`)
/// share the gate. They all have their own `load_detectors`
/// helpers that historically bypassed this check.
pub(crate) fn require_non_empty_detectors(
    detectors: &[DetectorSpec],
    detectors_path: &Path,
) -> Result<()> {
    if detectors.is_empty() {
        anyhow::bail!(
            "loaded zero detectors from {}. \
             Fix: verify the directory contains valid `*.toml` detector \
             specs (run `keyhog detectors --detectors {}` to see \
             which TOMLs were rejected, if any). Refusing to scan with \
             no detectors loaded - that would silently report `no \
             findings` regardless of what's in the source.",
            detectors_path.display(),
            detectors_path.display(),
        );
    }
    Ok(())
}

/// Load detectors from a directory, falling back to the embedded TOML
/// corpus when the directory is empty / non-existent / all-rejected.
///
/// `pub(crate)` so the per-subcommand modules (`watch`, `explain`,
/// `scan_system`, `detectors`) can each call this one helper instead of
/// shipping divergent copies. Pre-2026-05-24 each subcommand had its
/// own load+fallback wrapper and the copies had drifted on error
/// messages and on the fallback-to-embedded branch - kimi-dedup rows #4-6.
// `pub` (was pub(crate)) so the relocated explain test loads the embedded
// corpus through the same path production uses (no_inline_tests_in_src gate).
pub(crate) fn load_detectors_or_embedded(path: &Path) -> Result<Vec<DetectorSpec>> {
    validate_detector_path_for_scan(path)?;
    if path.exists() && path.is_dir() {
        let loaded = load_detectors(path).context("loading detectors from directory")?;
        require_non_empty_detectors(&loaded, path)?;
        return Ok(loaded);
    }
    load_detectors_embedded_or_fail(path)
}

pub(crate) fn detector_compile_failed(
    command: &str,
    detectors_path: &Path,
    error: impl fmt::Display,
) -> anyhow::Error {
    anyhow::anyhow!(
        "{command}: scanner compile failed while compiling detectors from '{}': {error}. \
         Fix: run `keyhog detectors --audit --detectors {}` and repair detector errors, \
         or omit --detectors to use the embedded corpus.",
        detectors_path.display(),
        detectors_path.display(),
    )
}

fn validate_detector_path_for_scan(path: &Path) -> Result<()> {
    if path.exists() && !path.is_dir() {
        anyhow::bail!(
            "detectors path '{}' is not a directory. \
             Fix: pass a directory containing detector TOML files, or omit \
             --detectors to use the embedded corpus.",
            path.display()
        );
    }
    if !path.exists() && path != Path::new("detectors") {
        anyhow::bail!(
            "detectors directory '{}' does not exist. \
             Fix: pass an existing detector directory, or omit --detectors to \
             use the embedded corpus.",
            path.display()
        );
    }
    Ok(())
}

fn load_detectors_embedded_or_fail(path: &Path) -> Result<Vec<DetectorSpec>> {
    // The embedded set being empty is the one runtime-actionable case (the binary
    // was built without baking in any detectors): tell the operator how to point
    // at an on-disk corpus instead. Everything past here delegates to the single
    // shared fail-closed loader in keyhog_core so every scan entry point parses
    // the compiled-in corpus byte-for-byte the same way.
    if keyhog_core::embedded_detector_count() == 0 {
        anyhow::bail!(
            "detectors directory '{}' not found and no embedded detectors available. \
             Fix: specify --detectors <path> or install a binary with embedded detectors",
            path.display()
        );
    }
    tracing::info!(
        embedded_count = keyhog_core::embedded_detector_count(),
        "using embedded detectors (no external detectors directory found)"
    );
    // Fails closed (returns `Err`) if ANY embedded detector TOML is malformed —
    // a corrupt compiled-in corpus is a hard error, never a silently-dropped
    // recall hole (Law 10).
    Ok(keyhog_core::load_embedded_detectors_or_fail()?)
}

pub(crate) fn build_scanner_config(args: &ScanArgs) -> ScannerConfig {
    // The preset (`--fast` / `--deep`) is a BASE, not a terminal state. It
    // seeds decode-depth / entropy / ml defaults; the per-flag overrides below
    // then layer on top. Pre-fix this function early-returned at the preset, so
    // `--deep --min-confidence 0.9` (or `--deep --entropy-threshold 5.0`, or any
    // `--known-prefixes` / keyword list) silently dropped the explicit override
    // - a coherence leak where "what the operator asked for" != "what ran". Only
    // `--no-decode` / `--no-entropy` are clap-conflicting with the presets
    // (`conflicts_with_all` on the `fast`/`deep` flags), so every other override
    // is a legitimate refinement of the preset base and must take effect.
    let mut config = if args.precision {
        ScannerConfig::high_precision()
    } else if args.fast {
        ScannerConfig::fast()
    } else if args.deep {
        ScannerConfig::thorough()
    } else {
        ScannerConfig::default()
    };

    if let Some(depth) = args.decode_depth {
        config.max_decode_depth = depth;
    }
    if args.no_decode {
        config.max_decode_depth = 0;
    }
    if let Some(size) = args.decode_size_limit {
        config.max_decode_bytes = size;
    }
    if let Some(conf) = args.min_confidence {
        // Under `--precision` the 0.85 floor is a MINIMUM the operator may
        // raise but not lower: `--precision --min-confidence 0.9` tightens to
        // 0.9, while `--precision --min-confidence 0.3` stays at 0.85 (the
        // documented "`--min-confidence` still overrides the floor on top"
        // contract is one-directional - it cannot punch a hole in the precision
        // bar). Every other mode lets the operator set the floor outright.
        config.min_confidence = if args.precision {
            conf.max(ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE)
        } else {
            conf
        };
    }
    // `--ml-threshold` is the documented "minimum ML confidence score for
    // generic entropy secrets" knob. Pre-fix it was parsed + range-validated
    // but never read by any non-test path, so `--ml-threshold 0.9` silently did
    // nothing (M21: a dead precision lever giving false confidence). Wire it as
    // a confidence FLOOR composed with `.max()` - mirroring the precision-mode
    // composition just above and the "minimum score" wording of the flag - so a
    // raised threshold tightens the bar a generic/entropy finding must clear,
    // while a lowered one can never punch below an operator's `--min-confidence`
    // (or the precision floor). Gated on a real move off the declared default
    // (`ML_THRESHOLD_DEFAULT`): an unset flag leaves the canonical 0.40 floor
    // untouched, so behaviour off the bug path is unchanged.
    if args.ml_threshold != ML_THRESHOLD_DEFAULT {
        config.min_confidence = config.min_confidence.max(args.ml_threshold);
    }
    // Keep the fixture opt-out coherent: skip both value suppressions and the
    // test/example path confidence penalty.
    config.penalize_test_paths = !args.no_suppress_test_fixtures;

    // `--no-entropy` conflicts with the presets at the clap layer, so under a
    // preset this is always `true` (entropy stays whatever the preset set). For
    // the no-preset path it honours the flag. Likewise `--no-decode` is preset-
    // conflicting; decode-depth above still applies for the no-preset path.
    if !(args.fast || args.deep || args.precision) {
        config.entropy_enabled = !args.no_entropy;
    }
    if let Some(threshold) = args.entropy_threshold {
        config.entropy_threshold = threshold;
    }
    if let Some(min_secret_len) = args.min_secret_len {
        config.min_secret_len = min_secret_len;
    }
    config.per_chunk_timeout_ms = args.per_chunk_timeout_ms;
    config.profile = args.profile;
    config.perf_trace = args.perf_trace;
    config.entropy_in_source_files = args.entropy_source_files;
    // Entropy candidates are scored through the MoE (model authoritative) by
    // default; `--no-entropy-ml-scoring` restores the legacy heuristic emit.
    // No-op unless entropy + ML are both on (gated in scan_entropy_fallback).
    config.entropy_ml_authoritative = !args.no_entropy_ml_scoring;
    // Keyword-anchored generic values use the relaxed entropy floor by default
    // (the keyword key is the evidence; precision carried by the MoE);
    // `--no-keyword-low-entropy` restores the high-entropy-only generic gate.
    // No-op unless the generic keyword bridge fires (scan_generic_assignments).
    // Composed with `&&` (not assigned) so the flag is one-directional: it can
    // only DISABLE the relaxed floor, never re-enable it under a preset that
    // turned it off (e.g. `--precision`, whose high_precision() base sets it
    // false). Mirrors the one-directional precision min_confidence contract.
    config.generic_keyword_low_entropy =
        config.generic_keyword_low_entropy && !args.no_keyword_low_entropy;
    config.scan_comments = args.scan_comments;
    config.ml_enabled = !args.fast && !args.no_ml;
    if let Some(weight) = args.ml_weight {
        config.ml_weight = weight;
    }
    config.unicode_normalization = !args.no_unicode_norm;
    if !args.known_prefixes.is_empty() {
        config.known_prefixes = args.known_prefixes.clone();
    }
    if !args.secret_keywords.is_empty() {
        config.secret_keywords = args.secret_keywords.clone();
    }
    if !args.test_keywords.is_empty() {
        config.test_keywords = args.test_keywords.clone();
    }
    if !args.placeholder_keywords.is_empty() {
        config.placeholder_keywords = args.placeholder_keywords.clone();
    }
    // Re-run the NaN/range safety net AFTER every CLI flag and `.keyhog.toml`
    // override has been merged in. `From<ScanConfig>` sanitises once at
    // construction time, but the overrides above (e.g. `config.ml_weight =
    // weight`, `config.entropy_threshold = threshold`) mutate the numeric
    // fields directly afterwards and would otherwise smuggle out-of-range
    // values straight to the engine: `--ml-weight 5.0` / `-1.0` (the ML blend
    // `w*ml + (1-w)*heuristic` in scan_postprocess relies on `w in [0,1]`) and
    // `--entropy-threshold 99` / `-5` (a threshold > 8.0 can never fire,
    // disabling the entropy detector; a negative one makes `entropy >= thr`
    // always true). Neither `--ml-weight` nor `--entropy-threshold` has a
    // clamping clap value_parser, so this is the only place the override layer
    // can honour the same invariant the `From` path enforces. Idempotent.
    config.sanitise();
    config
}

/// The single resolved scan configuration: the END of the precedence chain
/// `compiled-default -> [scan] table -> flat ConfigFile fields -> CLI flags`,
/// already merged into the engine's [`ScannerConfig`] PLUS the post-scan policy
/// the live worker needs (the per-detector confidence floors and the global
/// floor / ml gate read in `orchestrator/postprocess.rs`).
///
/// This exists to kill the "tuned != benched != shipped" leak: before it, the
/// scan-time floor lived in `ScannerConfig.min_confidence` (declared default
/// 0.5) while the post-scan floor was re-derived in `postprocess.rs` from
/// `args.min_confidence.unwrap_or(0.3)` - a SECOND, different literal, gated on
/// `!no_ml`. Two floors meant the value the operator set, the value the engine
/// applied, and the value postprocess applied could all disagree. Resolving
/// once and handing the live worker this struct makes "what runs" a single,
/// printable answer (see `keyhog config --effective`).
#[derive(Debug, Clone)]
pub(crate) struct ResolvedScanConfig {
    /// Explicit backend selected by `--backend`. `None` means autoroute/cache
    /// decides; shipped scans do not read backend selection from ambient env.
    pub(crate) backend_override: Option<keyhog_scanner::ScanBackend>,
    /// Force the coalesced batch scan pipeline. False means filesystem scans
    /// may use the fused filesystem pipeline when the backend/source contract
    /// permits it.
    pub(crate) batch_pipeline: bool,
    /// Explicit scan worker count from `--threads` / `[scan].threads`.
    /// `None` means the runtime uses the host physical-core default.
    pub(crate) threads: Option<usize>,
    /// Explicit filesystem reader thread count.
    pub(crate) reader_threads: Option<usize>,
    /// Fused filesystem pipeline chunk batch size.
    pub(crate) fused_batch: usize,
    /// Fused filesystem pipeline channel depth. `None` means derive from the
    /// configured worker pool at scan time.
    pub(crate) fused_depth: Option<usize>,
    /// Resolved GPU runtime policy for probe/init/degrade behavior.
    pub(crate) gpu_runtime_policy: keyhog_scanner::gpu::GpuRuntimePolicy,
    /// Whether autoroute calibration may include GPU candidates.
    pub(crate) autoroute_gpu: bool,
    /// Explicit scan execution mode that writes autoroute calibration evidence.
    /// This is intentionally not part of `autoroute_config_digest`: calibration
    /// records must be keyed to the normal scan identity they will serve.
    pub(crate) autoroute_calibration: bool,
    /// Engine-side config consumed by `CompiledScanner::with_config`.
    pub(crate) scanner: ScannerConfig,
    /// The global post-scan confidence floor a finding must clear to be
    /// reported. This is `scanner.min_confidence` - the SAME resolved value the
    /// engine uses, never a re-read of the raw args or a second literal. The
    /// live worker reads THIS, not `args.min_confidence.unwrap_or(0.3)`.
    pub(crate) min_confidence: f64,
    /// Whether ML confidence scoring is enabled. Mirrors `scanner.ml_enabled`.
    /// The post-scan floor applies regardless of this: disabling ML changes how
    /// confidence is *computed*, not whether a `--min-confidence` floor the
    /// operator set is honoured. (Pre-fix the floor was gated on `!no_ml`, so
    /// `--no-ml` silently bypassed `--min-confidence` entirely.)
    pub(crate) ml_enabled: bool,
    /// Per-detector floors from `.keyhog.toml` `[detector.<id>] min_confidence`.
    /// Take precedence over `min_confidence` for the matching detector id.
    pub(crate) detector_min_confidence: std::collections::HashMap<String, f64>,
    /// Detector ids disabled via `.keyhog.toml` `[detector.<id>] enabled = false`.
    /// These are dropped from the loaded corpus before scanner compilation.
    pub(crate) disabled_detectors: std::collections::HashSet<String>,
    /// Whether `.keyhog.toml` requires lockdown mode for this scan.
    pub(crate) require_lockdown: bool,
    /// Resolved regex lazy-DFA cache cap applied before scanner compilation.
    pub(crate) regex_dfa_limit: Option<usize>,
    /// Resolved Hyperscan compiled-database cache directory.
    pub(crate) hyperscan_cache_dir: Option<PathBuf>,
    /// Resolved persistent autoroute calibration cache file. `None` means
    /// persistence is explicitly disabled.
    pub(crate) autoroute_cache_path: Option<PathBuf>,
    /// Extra AWS canary/knockoff account IDs supplied by `.keyhog.toml`.
    pub(crate) aws_canary_accounts: Vec<String>,
    /// Explicit scanner route tuning supplied by `.keyhog.toml`.
    pub(crate) scanner_tuning: keyhog_scanner::ScannerTuningConfig,
    /// Resolved source byte/count limits applied while constructing sources.
    pub(crate) source_limits: keyhog_sources::SourceLimits,
}

/// Resolve the full scan configuration in one place: run the precedence merge
/// (compiled default -> `[scan]` table -> flat `ConfigFile` fields -> CLI flags)
/// via [`apply_config_file`], build the engine [`ScannerConfig`], and surface
/// the post-scan policy (global floor, ml gate, per-detector floors) so the live
/// worker consumes a resolved struct instead of re-reading raw args + a literal.
///
/// `args` is mutated in place by the config-file merge (CLI flags already win;
/// the merge only fills fields the operator left at their default), exactly as
/// the orchestrator's pre-existing `apply_config_file(&mut args)` call did. The
/// caller keeps the same `args` for the surfaces that still read it directly
/// (severity filter, dedup scope, verify/show-secrets gating).
pub(crate) fn resolve_scan_config(args: &mut ScanArgs) -> Result<ResolvedScanConfig> {
    let outcome = crate::config::apply_config_file(args);
    if !outcome.config_errors.is_empty() {
        anyhow::bail!(
            "invalid .keyhog.toml configuration:\n{}",
            outcome.config_errors.join("\n")
        );
    }
    keyhog_core::set_extra_trusted_dirs(outcome.trusted_bin_dirs.clone());
    let mut aws_canary_accounts = outcome.aws_canary_accounts;
    aws_canary_accounts.sort();
    aws_canary_accounts.dedup();
    let aws_canary_set = aws_canary_accounts.iter().cloned().collect();
    keyhog_core::set_extra_canary_accounts(aws_canary_set);
    configure_hyperscan_cache_dir(args.cache_dir.clone())?;
    let autoroute_cache_path =
        crate::autoroute_cache_path::resolve_autoroute_cache_path(args.autoroute_cache.as_deref())
            .map_err(anyhow::Error::msg)?;
    let backend_override = parse_backend_override(args.backend.as_deref())?;
    let batch_pipeline = args.batch_pipeline && !args.no_batch_pipeline;
    let threads = args.threads;
    let reader_threads = args.reader_threads;
    let fused_batch = args.fused_batch.unwrap_or(FUSED_BATCH_DEFAULT); // LAW10: absent fused-batch config => documented compiled throughput default; no recall path changes and the value is printed/hashes into autoroute identity
    let fused_depth = args.fused_depth;
    let gpu_runtime_policy = gpu_runtime_policy_from_args(args);
    let autoroute_gpu = args.autoroute_gpu && !args.no_autoroute_gpu;
    let autoroute_calibration = args.autoroute_calibrate;
    let scanner_tuning = outcome.scanner_tuning;
    let scanner = build_scanner_config(args);
    // The post-scan floor is the SAME value the engine resolved - read it back
    // off the built config rather than re-deriving from `args`, so the two can
    // never drift. `ScannerConfig::from`/`sanitise` already clamped NaN/range.
    let min_confidence = scanner.min_confidence;
    let ml_enabled = scanner.ml_enabled;
    Ok(ResolvedScanConfig {
        backend_override,
        batch_pipeline,
        threads,
        reader_threads,
        fused_batch,
        fused_depth,
        gpu_runtime_policy,
        autoroute_gpu,
        autoroute_calibration,
        scanner,
        min_confidence,
        ml_enabled,
        detector_min_confidence: outcome.detector_min_confidence,
        disabled_detectors: outcome.disabled_detectors.into_iter().collect(),
        require_lockdown: outcome.require_lockdown,
        regex_dfa_limit: args.regex_dfa_limit,
        hyperscan_cache_dir: args.cache_dir.clone(),
        autoroute_cache_path,
        aws_canary_accounts,
        scanner_tuning,
        source_limits: args.limits.to_source_limits(),
    })
}

pub(crate) fn resolved_scan_config_for_scanner(scanner: ScannerConfig) -> ResolvedScanConfig {
    let min_confidence = scanner.min_confidence;
    let ml_enabled = scanner.ml_enabled;
    ResolvedScanConfig {
        backend_override: None,
        batch_pipeline: false,
        threads: None,
        reader_threads: None,
        fused_batch: FUSED_BATCH_DEFAULT,
        fused_depth: None,
        gpu_runtime_policy: keyhog_scanner::gpu::GpuRuntimePolicy::Auto,
        autoroute_gpu: false,
        autoroute_calibration: false,
        scanner,
        min_confidence,
        ml_enabled,
        detector_min_confidence: std::collections::HashMap::new(),
        disabled_detectors: std::collections::HashSet::new(),
        require_lockdown: false,
        regex_dfa_limit: None,
        hyperscan_cache_dir: None,
        autoroute_cache_path: None,
        aws_canary_accounts: Vec::new(),
        scanner_tuning: keyhog_scanner::ScannerTuningConfig::default(),
        source_limits: keyhog_sources::SourceLimits::default(),
    }
}

/// Render the resolved scan config as a stable, human + machine readable block
/// for `keyhog config --effective`. It
/// answers "what will actually run?" in one place: the resolved engine config
/// AND the post-scan floors, so a test (or an operator) can assert that the
/// tuned value, the benched value, and the shipped value are the same number.
///
/// Emitted as deterministic `key = value` lines (sorted detector floors) rather
/// than JSON so it is greppable and diffable in dogfood snapshots without a
/// serde derive on the engine `ScannerConfig` (which lives in another crate).
pub(crate) fn render_effective_config(resolved: &ResolvedScanConfig) -> String {
    let s = &resolved.scanner;
    let mut out = String::new();
    out.push_str("[effective-config]\n");
    out.push_str(&format!(
        "backend = {}\n",
        backend_override_label(resolved.backend_override)
    ));
    out.push_str(&format!("batch_pipeline = {}\n", resolved.batch_pipeline));
    out.push_str(&format!(
        "threads = {}\n",
        resolved
            .threads
            .map_or_else(|| "auto".to_string(), |n| n.to_string())
    ));
    out.push_str(&format!(
        "reader_threads = {}\n",
        resolved
            .reader_threads
            .map_or_else(|| "auto".to_string(), |n| n.to_string())
    ));
    out.push_str(&format!("fused_batch = {}\n", resolved.fused_batch));
    out.push_str(&format!(
        "fused_depth = {}\n",
        resolved
            .fused_depth
            .map_or_else(|| "auto".to_string(), |n| n.to_string())
    ));
    out.push_str(&format!("gpu = {}\n", resolved.gpu_runtime_policy));
    out.push_str(&format!("autoroute_gpu = {}\n", resolved.autoroute_gpu));
    out.push_str(&format!(
        "autoroute_calibration = {}\n",
        resolved.autoroute_calibration
    ));
    out.push_str(&format!("profile = {}\n", s.profile));
    out.push_str(&format!("perf_trace = {}\n", s.perf_trace));
    out.push_str(&format!("min_confidence = {}\n", resolved.min_confidence));
    out.push_str(&format!("ml_enabled = {}\n", resolved.ml_enabled));
    out.push_str(&format!("ml_weight = {}\n", s.ml_weight));
    out.push_str(&format!("entropy_enabled = {}\n", s.entropy_enabled));
    out.push_str(&format!(
        "entropy_ml_authoritative = {}\n",
        s.entropy_ml_authoritative
    ));
    out.push_str(&format!(
        "generic_keyword_low_entropy = {}\n",
        s.generic_keyword_low_entropy
    ));
    out.push_str(&format!("entropy_threshold = {}\n", s.entropy_threshold));
    out.push_str(&format!(
        "entropy_in_source_files = {}\n",
        s.entropy_in_source_files
    ));
    out.push_str(&format!("max_decode_depth = {}\n", s.max_decode_depth));
    out.push_str(&format!("max_decode_bytes = {}\n", s.max_decode_bytes));
    out.push_str(&format!(
        "per_chunk_timeout_ms = {}\n",
        s.per_chunk_timeout_ms
            .map_or_else(|| "off".to_string(), |ms| ms.to_string())
    ));
    let limits = resolved.source_limits;
    out.push_str(&format!("limit_stdin_bytes = {}\n", limits.stdin_bytes));
    out.push_str(&format!(
        "limit_web_response_bytes = {}\n",
        limits.web_response_bytes
    ));
    out.push_str(&format!(
        "limit_s3_object_bytes = {}\n",
        limits.s3_object_bytes
    ));
    out.push_str(&format!(
        "limit_gcs_object_bytes = {}\n",
        limits.gcs_object_bytes
    ));
    out.push_str(&format!(
        "limit_azure_blob_bytes = {}\n",
        limits.azure_blob_bytes
    ));
    out.push_str(&format!(
        "limit_docker_tar_entry_bytes = {}\n",
        limits.docker_tar_entry_bytes
    ));
    out.push_str(&format!(
        "limit_docker_image_config_bytes = {}\n",
        limits.docker_image_config_bytes
    ));
    out.push_str(&format!(
        "limit_docker_tar_total_bytes = {}\n",
        limits.docker_tar_total_bytes
    ));
    out.push_str(&format!(
        "limit_git_line_bytes = {}\n",
        limits.git_line_bytes
    ));
    out.push_str(&format!(
        "limit_git_total_bytes = {}\n",
        limits.git_total_bytes
    ));
    out.push_str(&format!(
        "limit_git_blob_bytes = {}\n",
        limits.git_blob_bytes
    ));
    out.push_str(&format!("limit_git_chunks = {}\n", limits.git_chunk_count));
    out.push_str(&format!(
        "limit_binary_read_bytes = {}\n",
        limits.binary_read_bytes
    ));
    out.push_str(&format!(
        "limit_binary_decompiled_bytes = {}\n",
        limits.binary_decompiled_bytes
    ));
    out.push_str(&format!("scan_comments = {}\n", s.scan_comments));
    out.push_str(&format!(
        "unicode_normalization = {}\n",
        s.unicode_normalization
    ));
    out.push_str(&format!(
        "disabled_detectors = {}\n",
        resolved.disabled_detectors.len()
    ));
    let cache_dir = resolved
        .hyperscan_cache_dir
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<platform default>".to_string()); // LAW10: reporting-only label for an unset optional cache-dir; scan compilation still resolves and validates the platform default before use.
    out.push_str(&format!("hyperscan_cache_dir = {cache_dir}\n"));
    let autoroute_cache_path = resolved
        .autoroute_cache_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<disabled>".to_string()); // LAW10: reporting-only label for explicit disabled autoroute persistence; scan either has a path or fails before benchmarking.
    out.push_str(&format!("autoroute_cache_path = {autoroute_cache_path}\n"));
    out.push_str(&format!(
        "aws_canary_accounts = {}\n",
        resolved.aws_canary_accounts.len()
    ));
    let tuning = resolved.scanner_tuning.effective();
    out.push_str(&format!("tuning_fallback_hs = {}\n", tuning.fallback_hs));
    out.push_str(&format!(
        "tuning_hs_prefilter_max_len = {}\n",
        tuning.hs_prefilter_max_len
    ));
    out.push_str(&format!(
        "tuning_hs_shard_target = {}\n",
        tuning.hs_shard_target
    ));
    out.push_str(&format!(
        "tuning_fallback_anchor = {}\n",
        tuning.fallback_anchor
    ));
    out.push_str(&format!(
        "tuning_homoglyph_gate = {}\n",
        tuning.homoglyph_gate
    ));
    out.push_str(&format!(
        "tuning_homoglyph_ascii_skip = {}\n",
        tuning.homoglyph_ascii_skip
    ));
    out.push_str(&format!(
        "tuning_fallback_reverse = {}\n",
        tuning.fallback_reverse
    ));
    out.push_str(&format!(
        "tuning_prefilter_truncate = {}\n",
        tuning.prefilter_truncate
    ));
    out.push_str(&format!(
        "tuning_fallback_prefix_gate = {}\n",
        tuning.fallback_prefix_gate
    ));
    out.push_str(&format!("tuning_decode_focus = {}\n", tuning.decode_focus));
    out.push_str(&format!(
        "tuning_confirmed_suffix_gate = {}\n",
        tuning.confirmed_suffix_gate
    ));
    out.push_str(&format!(
        "tuning_no_candidate_gate = {}\n",
        tuning.no_candidate_gate
    ));
    out.push_str(&format!(
        "tuning_fallback_localizer = {}\n",
        tuning.fallback_localizer
    ));
    out.push_str(&format!(
        "tuning_gpu_recall_floor = {}\n",
        tuning.gpu_recall_floor
    ));
    out.push_str(&format!(
        "tuning_gpu_moe_timeout_ms = {}\n",
        tuning.gpu_moe_timeout_ms
    ));
    out.push_str(&format!("known_prefixes = {}\n", s.known_prefixes.len()));
    out.push_str(&format!("secret_keywords = {}\n", s.secret_keywords.len()));
    out.push_str(&format!("test_keywords = {}\n", s.test_keywords.len()));
    out.push_str(&format!(
        "placeholder_keywords = {}\n",
        s.placeholder_keywords.len()
    ));
    let mut floors: Vec<(&String, &f64)> = resolved.detector_min_confidence.iter().collect();
    floors.sort_by(|a, b| a.0.cmp(b.0));
    for (id, floor) in floors {
        out.push_str(&format!("detector_min_confidence.{id} = {floor}\n"));
    }
    out
}

/// Stable-enough fingerprint for autoroute cache identity. It is computed from
/// the resolved config that actually reaches the engine/postprocess layer, so
/// `.keyhog.toml`, presets, CLI overrides, and host caps all invalidate routing
/// together when they change scan cost or candidate volume.
pub(crate) fn autoroute_config_digest(resolved: &ResolvedScanConfig) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let s = &resolved.scanner;
    s.min_confidence.to_bits().hash(&mut h);
    s.ml_enabled.hash(&mut h);
    s.ml_weight.to_bits().hash(&mut h);
    s.entropy_enabled.hash(&mut h);
    s.entropy_ml_authoritative.hash(&mut h);
    s.generic_keyword_low_entropy.hash(&mut h);
    s.entropy_threshold.to_bits().hash(&mut h);
    s.entropy_in_source_files.hash(&mut h);
    s.max_decode_depth.hash(&mut h);
    s.max_decode_bytes.hash(&mut h);
    s.per_chunk_timeout_ms.hash(&mut h);
    s.max_matches_per_chunk.hash(&mut h);
    s.scan_comments.hash(&mut h);
    s.unicode_normalization.hash(&mut h);
    s.penalize_test_paths.hash(&mut h);
    s.multiline.max_join_lines.hash(&mut h);
    s.multiline.python_implicit.hash(&mut h);
    s.multiline.backslash_continuation.hash(&mut h);
    s.multiline.plus_concatenation.hash(&mut h);
    s.multiline.template_literals.hash(&mut h);
    hash_strings(&s.known_prefixes, &mut h);
    hash_strings(&s.secret_keywords, &mut h);
    hash_strings(&s.test_keywords, &mut h);
    hash_strings(&s.placeholder_keywords, &mut h);
    resolved.min_confidence.to_bits().hash(&mut h);
    resolved.ml_enabled.hash(&mut h);
    let mut floors: Vec<_> = resolved.detector_min_confidence.iter().collect();
    floors.sort_by(|a, b| a.0.cmp(b.0));
    for (id, floor) in floors {
        id.hash(&mut h);
        floor.to_bits().hash(&mut h);
    }
    let mut disabled: Vec<_> = resolved.disabled_detectors.iter().collect();
    disabled.sort();
    for id in disabled {
        id.hash(&mut h);
    }
    resolved.require_lockdown.hash(&mut h);
    backend_override_label(resolved.backend_override).hash(&mut h);
    resolved.batch_pipeline.hash(&mut h);
    resolved.threads.hash(&mut h);
    resolved.reader_threads.hash(&mut h);
    resolved.fused_batch.hash(&mut h);
    resolved.fused_depth.hash(&mut h);
    resolved.gpu_runtime_policy.hash(&mut h);
    resolved.autoroute_gpu.hash(&mut h);
    resolved.regex_dfa_limit.hash(&mut h);
    resolved.hyperscan_cache_dir.hash(&mut h);
    resolved.aws_canary_accounts.hash(&mut h);
    resolved.scanner_tuning.hash(&mut h);
    resolved.source_limits.hash(&mut h);
    h.finish()
}

fn hash_strings(strings: &[String], h: &mut impl std::hash::Hasher) {
    use std::hash::Hash;
    strings.len().hash(h);
    for s in strings {
        s.hash(h);
    }
}

#[doc(hidden)]
pub(crate) mod testing {
    use crate::args::ScanArgs;
    use anyhow::Result;
    use keyhog_core::DetectorSpec;
    use keyhog_scanner::ScannerConfig;
    use std::path::Path;

    pub(crate) const MAX_THREADS_CAP: usize = super::MAX_THREADS_CAP;
    pub(crate) const ML_THRESHOLD_DEFAULT: f64 = super::ML_THRESHOLD_DEFAULT;

    pub(crate) fn sanitise_thread_count(
        requested: usize,
        physical_cores: usize,
        source: &'static str,
    ) -> usize {
        super::sanitise_thread_count(requested, physical_cores, source)
    }

    pub(crate) fn load_detectors_or_embedded(path: &Path) -> Result<Vec<DetectorSpec>> {
        super::load_detectors_or_embedded(path)
    }

    pub(crate) fn load_detectors_from_dir_with_cache(
        source_dir: &Path,
        cache_path: &Path,
    ) -> Result<Vec<DetectorSpec>> {
        super::load_detectors_from_dir_with_cache(source_dir, cache_path)
    }

    pub(crate) fn build_scanner_config(args: &ScanArgs) -> ScannerConfig {
        super::build_scanner_config(args)
    }

    pub(crate) fn resolve_scan_config(args: &mut ScanArgs) -> anyhow::Result<()> {
        super::resolve_scan_config(args).map(|_| ())
    }

    pub(crate) fn resolve_scan_config_aws_canary_accounts(
        args: &mut ScanArgs,
    ) -> anyhow::Result<Vec<String>> {
        super::resolve_scan_config(args).map(|resolved| resolved.aws_canary_accounts)
    }

    pub(crate) fn render_effective_config_for_scanner(scanner: ScannerConfig) -> String {
        let resolved = resolved_config_for_scanner(scanner);
        super::render_effective_config(&resolved)
    }

    pub(crate) fn autoroute_config_digest_for_scanner(scanner: ScannerConfig) -> u64 {
        let resolved = resolved_config_for_scanner(scanner);
        super::autoroute_config_digest(&resolved)
    }

    pub(crate) fn autoroute_config_digest_for_scanner_with_autoroute_gpu(
        scanner: ScannerConfig,
        autoroute_gpu: bool,
    ) -> u64 {
        let mut resolved = resolved_config_for_scanner(scanner);
        resolved.autoroute_gpu = autoroute_gpu;
        super::autoroute_config_digest(&resolved)
    }

    fn resolved_config_for_scanner(scanner: ScannerConfig) -> super::ResolvedScanConfig {
        let min_confidence = scanner.min_confidence;
        let ml_enabled = scanner.ml_enabled;
        super::ResolvedScanConfig {
            backend_override: None,
            batch_pipeline: false,
            threads: None,
            reader_threads: None,
            fused_batch: super::FUSED_BATCH_DEFAULT,
            fused_depth: None,
            gpu_runtime_policy: keyhog_scanner::gpu::GpuRuntimePolicy::Auto,
            autoroute_gpu: false,
            autoroute_calibration: false,
            scanner,
            min_confidence,
            ml_enabled,
            detector_min_confidence: std::collections::HashMap::new(),
            disabled_detectors: std::collections::HashSet::new(),
            require_lockdown: false,
            regex_dfa_limit: None,
            hyperscan_cache_dir: None,
            autoroute_cache_path: None,
            aws_canary_accounts: Vec::new(),
            scanner_tuning: keyhog_scanner::ScannerTuningConfig::default(),
            source_limits: keyhog_sources::SourceLimits::default(),
        }
    }
}
