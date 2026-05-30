use crate::args::ScanArgs;
use anyhow::{Context, Result};
use keyhog_core::{load_detectors, DetectorSpec};
use keyhog_scanner::ScannerConfig;
use std::path::{Path, PathBuf};

/// Hard ceiling on the parallel thread count. Above this, thread
/// creation overhead + scheduler contention dominates any throughput
/// gain on CPU-bound work. Matches the cap the rayon docs recommend
/// for general-purpose pools and protects against `--threads 9999999`
/// misconfiguration that would either OOM-on-spawn or thrash the
/// scheduler on a 4-core box.
/// Hard ceiling on the worker thread count. Requested values above this are
/// clamped (and logged) by [`sanitise_thread_count`]; spawning thousands of
/// threads thrashes the OS scheduler without speeding the scan up.
pub const MAX_THREADS_CAP: usize = 256;

pub(crate) fn configure_threads(threads: Option<usize>, physical_cores: usize) {
    // Resolution order: --threads CLI arg > KEYHOG_THREADS env > physical core
    // count. Physical (not logical) is the right default for CPU-bound regex
    // - SMT/Hyperthreading siblings share execution units, so 2× the threads
    // yields ~1.1× the throughput while doubling cache pressure.
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
    } else if let Ok(env) = std::env::var("KEYHOG_THREADS") {
        match env.parse::<usize>() {
            Ok(t) => (
                sanitise_thread_count(t, physical_cores, "env:KEYHOG_THREADS"),
                "env:KEYHOG_THREADS",
            ),
            Err(_) => {
                tracing::warn!(value = %env, "ignoring invalid KEYHOG_THREADS value");
                (physical_cores.max(1), "physical-cores")
            }
        }
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

/// Clamp a user-supplied thread count to a sane range. Logs a
/// warning when the value was outside the accepted bounds so an
/// operator who passed `--threads 0` or `--threads 999999` sees what
/// the scanner actually used.
fn sanitise_thread_count(requested: usize, physical_cores: usize, source: &'static str) -> usize {
    let safe_default = physical_cores.max(1);
    if requested == 0 {
        tracing::warn!(
            source,
            requested = 0,
            using = safe_default,
            "thread count of 0 is not meaningful; falling back to physical-cores"
        );
        return safe_default;
    }
    if requested > MAX_THREADS_CAP {
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

#[doc(hidden)]
#[allow(dead_code)]
pub fn sanitise_thread_count_for_test(
    requested: usize,
    physical_cores: usize,
    source: &'static str,
) -> usize {
    sanitise_thread_count(requested, physical_cores, source)
}

pub(crate) fn auto_discover_detectors(path: &Path) -> Result<PathBuf> {
    if let Ok(env_path) = std::env::var("KEYHOG_DETECTORS") {
        let p = PathBuf::from(&env_path);
        if p.exists() && p.is_dir() {
            return Ok(p);
        }
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
                .ok()
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
    if path.exists() && path.is_dir() {
        // The parse cache lives in the user's XDG cache dir, NOT inside the
        // detectors directory. A system install puts detectors under a
        // root-owned, read-only tree (e.g. /opt/keyhog/detectors,
        // /usr/share/keyhog/detectors); writing `.keyhog-cache.json` there
        // failed with `Permission denied` on EVERY run, spamming two WARN
        // lines and silently re-parsing each time. Keying the cache by the
        // source dir keeps distinct detector directories from colliding;
        // `load_detector_cache` still mtime-checks the source TOMLs for
        // staleness regardless of where the cache file lives.
        let cache_path = detector_cache_path(path);
        if let Some(cache_path) = &cache_path {
            if let Some(cached) = keyhog_core::load_detector_cache(cache_path, path) {
                require_non_empty_detectors(&cached, path)?;
                return Ok(cached);
            }
        }
        let loaded = load_detectors(path)?;
        require_non_empty_detectors(&loaded, path)?;
        if let Some(cache_path) = &cache_path {
            if let Err(error) = keyhog_core::save_detector_cache(&loaded, cache_path) {
                // A read-only or absent cache dir is not an error the operator
                // can act on and not worth a per-run WARN: the scan proceeds,
                // just without the (small) parse-cache speedup. Debug-level so
                // `-v` still surfaces it for diagnosis.
                tracing::debug!(
                    cache_path = %cache_path.display(),
                    %error,
                    "detector parse cache not written (cache dir unwritable); \
                     re-parsing TOML each run"
                );
            }
        }
        return Ok(loaded);
    }
    load_detectors_embedded_or_fail(path)
}

/// Path to the detector parse cache in the user's XDG cache dir, keyed by the
/// source directory so multiple `--detectors` trees don't collide. Returns
/// `None` when no cache dir is resolvable (cache simply disabled). The
/// `.json` is created on first successful parse and revalidated against the
/// source TOMLs' mtimes by `keyhog_core::load_detector_cache`.
fn detector_cache_path(source_dir: &Path) -> Option<std::path::PathBuf> {
    use std::hash::{Hash, Hasher};
    let canonical = std::fs::canonicalize(source_dir).unwrap_or_else(|_| source_dir.to_path_buf());
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
             specs (run `keyhog detectors list --detectors {}` to see \
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
pub fn load_detectors_or_embedded(path: &Path) -> Result<Vec<DetectorSpec>> {
    if path.exists() && path.is_dir() {
        let loaded = load_detectors(path).context("loading detectors from directory")?;
        require_non_empty_detectors(&loaded, path)?;
        return Ok(loaded);
    }
    load_detectors_embedded_or_fail(path)
}

fn load_detectors_embedded_or_fail(path: &Path) -> Result<Vec<DetectorSpec>> {
    let embedded = keyhog_core::embedded_detector_tomls();
    if !embedded.is_empty() {
        tracing::info!(
            embedded_count = embedded.len(),
            "using embedded detectors (no external detectors directory found)"
        );
        let mut detectors = Vec::new();
        for (name, toml_content) in embedded {
            match toml::from_str::<keyhog_core::DetectorFile>(toml_content) {
                Ok(file) => detectors.push(file.detector),
                Err(error) => {
                    tracing::debug!("failed to parse embedded detector {}: {}", name, error)
                }
            }
        }
        if detectors.is_empty() {
            anyhow::bail!(
                "no detectors loaded from embedded data - every embedded TOML \
                 failed to parse. Fix: pass `--detectors <DIR>` to load from a \
                 directory of TOMLs, or rebuild keyhog from source so the \
                 build.rs detector-embedding step re-runs."
            );
        }
        return Ok(detectors);
    }

    anyhow::bail!(
        "detectors directory '{}' not found and no embedded detectors available. \
         Fix: specify --detectors <path> or set KEYHOG_DETECTORS env var",
        path.display()
    )
}

pub fn build_scanner_config(args: &ScanArgs) -> ScannerConfig {
    // The preset (`--fast` / `--deep`) is a BASE, not a terminal state. It
    // seeds decode-depth / entropy / ml defaults; the per-flag overrides below
    // then layer on top. Pre-fix this function early-returned at the preset, so
    // `--deep --min-confidence 0.9` (or `--deep --entropy-threshold 5.0`, or any
    // `--known-prefixes` / keyword list) silently dropped the explicit override
    // - a coherence leak where "what the operator asked for" != "what ran". Only
    // `--no-decode` / `--no-entropy` are clap-conflicting with the presets
    // (`conflicts_with_all` on the `fast`/`deep` flags), so every other override
    // is a legitimate refinement of the preset base and must take effect.
    let mut config = if args.fast {
        ScannerConfig::fast()
    } else if args.deep {
        ScannerConfig::thorough()
    } else {
        ScannerConfig::default()
    };

    if let Some(depth) = args.decode_depth {
        config.max_decode_depth = depth;
    }
    if let Some(size) = args.decode_size_limit {
        config.max_decode_bytes = size;
    }
    if let Some(conf) = args.min_confidence {
        config.min_confidence = conf;
    }

    // `--no-entropy` conflicts with the presets at the clap layer, so under a
    // preset this is always `true` (entropy stays whatever the preset set). For
    // the no-preset path it honours the flag. Likewise `--no-decode` is preset-
    // conflicting; decode-depth above still applies for the no-preset path.
    if !(args.fast || args.deep) {
        config.entropy_enabled = !args.no_entropy;
    }
    if let Some(threshold) = args.entropy_threshold {
        config.entropy_threshold = threshold;
    }
    config.entropy_in_source_files = args.entropy_source_files;
    config.scan_comments = args.scan_comments;
    config.ml_enabled = !args.no_ml;
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
/// printable answer (see `--print-effective-config`).
#[derive(Debug, Clone)]
pub struct ResolvedScanConfig {
    /// Engine-side config consumed by `CompiledScanner::with_config`.
    pub scanner: ScannerConfig,
    /// The global post-scan confidence floor a finding must clear to be
    /// reported. This is `scanner.min_confidence` - the SAME resolved value the
    /// engine uses, never a re-read of the raw args or a second literal. The
    /// live worker reads THIS, not `args.min_confidence.unwrap_or(0.3)`.
    pub min_confidence: f64,
    /// Whether ML confidence scoring is enabled. Mirrors `scanner.ml_enabled`.
    /// The post-scan floor applies regardless of this: disabling ML changes how
    /// confidence is *computed*, not whether a `--min-confidence` floor the
    /// operator set is honoured. (Pre-fix the floor was gated on `!no_ml`, so
    /// `--no-ml` silently bypassed `--min-confidence` entirely.)
    pub ml_enabled: bool,
    /// Per-detector floors from `.keyhog.toml` `[detector.<id>] min_confidence`.
    /// Take precedence over `min_confidence` for the matching detector id.
    pub detector_min_confidence: std::collections::HashMap<String, f64>,
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
pub fn resolve_scan_config(args: &mut ScanArgs) -> ResolvedScanConfig {
    let outcome = crate::config::apply_config_file(args);
    let scanner = build_scanner_config(args);
    // The post-scan floor is the SAME value the engine resolved - read it back
    // off the built config rather than re-deriving from `args`, so the two can
    // never drift. `ScannerConfig::from`/`sanitise` already clamped NaN/range.
    let min_confidence = scanner.min_confidence;
    let ml_enabled = scanner.ml_enabled;
    ResolvedScanConfig {
        scanner,
        min_confidence,
        ml_enabled,
        detector_min_confidence: outcome.detector_min_confidence,
    }
}

/// Hidden `--print-effective-config` surface: the coherence oracle. Returns
/// `true` when the dump was requested (the caller should then print-and-exit
/// SUCCESS without scanning), `false` for a normal scan.
///
/// Triggered today by the `KEYHOG_PRINT_EFFECTIVE_CONFIG=1` env var, matching
/// the existing env-or-flag precedent (`KEYHOG_BACKEND`/`--backend`,
/// `KEYHOG_THREADS`/`--threads`). The hidden `--print-effective-config` clap
/// flag (a field on `ScanArgs`, wired by the args owner) should set that env
/// var or call this same helper, so the two surfaces share one code path. The
/// env path keeps the oracle functional for tooling / dogfood snapshots
/// independent of the clap layer. Writes the rendered block to stdout so it is
/// captured by the same `--output`-less stdout path the formatted report uses.
pub fn print_effective_config_if_requested(resolved: &ResolvedScanConfig) -> bool {
    let requested = std::env::var("KEYHOG_PRINT_EFFECTIVE_CONFIG")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !requested {
        return false;
    }
    print!("{}", render_effective_config(resolved));
    true
}

/// Render the resolved scan config as a stable, human + machine readable block
/// for the hidden `--print-effective-config` flag - the coherence oracle. It
/// answers "what will actually run?" in one place: the resolved engine config
/// AND the post-scan floors, so a test (or an operator) can assert that the
/// tuned value, the benched value, and the shipped value are the same number.
///
/// Emitted as deterministic `key = value` lines (sorted detector floors) rather
/// than JSON so it is greppable and diffable in dogfood snapshots without a
/// serde derive on the engine `ScannerConfig` (which lives in another crate).
pub fn render_effective_config(resolved: &ResolvedScanConfig) -> String {
    use std::fmt::Write as _;
    let s = &resolved.scanner;
    let mut out = String::new();
    let _ = writeln!(out, "[effective-config]");
    let _ = writeln!(out, "min_confidence = {}", resolved.min_confidence);
    let _ = writeln!(out, "ml_enabled = {}", resolved.ml_enabled);
    let _ = writeln!(out, "ml_weight = {}", s.ml_weight);
    let _ = writeln!(out, "entropy_enabled = {}", s.entropy_enabled);
    let _ = writeln!(out, "entropy_threshold = {}", s.entropy_threshold);
    let _ = writeln!(
        out,
        "entropy_in_source_files = {}",
        s.entropy_in_source_files
    );
    let _ = writeln!(out, "max_decode_depth = {}", s.max_decode_depth);
    let _ = writeln!(out, "max_decode_bytes = {}", s.max_decode_bytes);
    let _ = writeln!(out, "scan_comments = {}", s.scan_comments);
    let _ = writeln!(out, "unicode_normalization = {}", s.unicode_normalization);
    let _ = writeln!(out, "known_prefixes = {}", s.known_prefixes.len());
    let _ = writeln!(out, "secret_keywords = {}", s.secret_keywords.len());
    let _ = writeln!(out, "test_keywords = {}", s.test_keywords.len());
    let _ = writeln!(
        out,
        "placeholder_keywords = {}",
        s.placeholder_keywords.len()
    );
    let mut floors: Vec<(&String, &f64)> = resolved.detector_min_confidence.iter().collect();
    floors.sort_by(|a, b| a.0.cmp(b.0));
    for (id, floor) in floors {
        let _ = writeln!(out, "detector_min_confidence.{id} = {floor}");
    }
    out
}
