use crate::args::{CliDedupScope, ScanArgs, SeverityFilter};
use anyhow::Result;
use keyhog_scanner::ScannerConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod detectors;
mod effective;
mod runtime;

pub(crate) use detectors::{
    auto_discover_detectors, detector_compile_failed, load_detectors_no_cache,
    load_detectors_or_embedded, load_detectors_with_cache,
};
pub(crate) use effective::{autoroute_config_digest, render_effective_config};
pub(crate) use runtime::{
    FUSED_BATCH_DEFAULT, MAX_THREADS_CAP, ML_THRESHOLD_DEFAULT, backend_override_label,
    configure_hyperscan_cache_dir, configure_threads, fused_depth_default,
    gpu_runtime_policy_from_args, parse_backend_override,
};

#[derive(Debug, Clone)]
struct ScannerConfigInput {
    precision: bool,
    fast: bool,
    deep: bool,
    decode_depth: Option<usize>,
    no_decode: bool,
    decode_size_limit: Option<usize>,
    min_confidence: Option<f64>,
    ml_threshold: f64,
    no_suppress_test_fixtures: bool,
    no_entropy: bool,
    entropy_threshold: Option<f64>,
    min_secret_len: Option<usize>,
    per_chunk_timeout_ms: Option<u64>,
    profile: bool,
    perf_trace: bool,
    entropy_source_files: bool,
    no_entropy_ml_scoring: bool,
    no_keyword_low_entropy: bool,
    scan_comments: bool,
    no_ml: bool,
    ml_weight: Option<f64>,
    no_unicode_norm: bool,
    known_prefixes: Vec<String>,
    secret_keywords: Vec<String>,
    test_keywords: Vec<String>,
    placeholder_keywords: Vec<String>,
}

impl ScannerConfigInput {
    fn from_scan_args(args: &ScanArgs) -> Self {
        Self {
            precision: args.precision,
            fast: args.fast,
            deep: args.deep,
            decode_depth: args.decode_depth,
            no_decode: args.no_decode,
            decode_size_limit: args.decode_size_limit,
            min_confidence: args.min_confidence,
            ml_threshold: args.ml_threshold,
            no_suppress_test_fixtures: args.no_suppress_test_fixtures,
            no_entropy: args.no_entropy,
            entropy_threshold: args.entropy_threshold,
            min_secret_len: args.min_secret_len,
            per_chunk_timeout_ms: args.per_chunk_timeout_ms,
            profile: args.profile,
            perf_trace: args.perf_trace,
            entropy_source_files: args.entropy_source_files,
            no_entropy_ml_scoring: args.no_entropy_ml_scoring,
            no_keyword_low_entropy: args.no_keyword_low_entropy,
            scan_comments: args.scan_comments,
            no_ml: args.no_ml,
            ml_weight: args.ml_weight,
            no_unicode_norm: args.no_unicode_norm,
            known_prefixes: args.known_prefixes.clone(),
            secret_keywords: args.secret_keywords.clone(),
            test_keywords: args.test_keywords.clone(),
            placeholder_keywords: args.placeholder_keywords.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct ScanRuntimeInput {
    cache_dir: Option<PathBuf>,
    autoroute_cache: Option<String>,
    calibration_cache: Option<PathBuf>,
    backend: Option<String>,
    batch_pipeline: bool,
    threads: Option<usize>,
    reader_threads: Option<usize>,
    fused_batch: usize,
    fused_depth: Option<usize>,
    gpu_runtime_policy: keyhog_scanner::gpu::GpuRuntimePolicy,
    autoroute_gpu: bool,
    autoroute_calibration: bool,
    regex_dfa_limit: Option<usize>,
    source_limits: keyhog_sources::SourceLimits,
}

impl ScanRuntimeInput {
    fn from_scan_args(args: &ScanArgs) -> Self {
        Self {
            cache_dir: args.cache_dir.clone(),
            autoroute_cache: args.autoroute_cache.clone(),
            calibration_cache: args.calibration_cache.clone(),
            backend: args.backend.clone(),
            batch_pipeline: args.batch_pipeline && !args.no_batch_pipeline,
            threads: args.threads,
            reader_threads: args.reader_threads,
            fused_batch: args.fused_batch.unwrap_or(FUSED_BATCH_DEFAULT), // LAW10: absent fused-batch config => documented compiled throughput default; no recall path changes and the value is printed/hashes into autoroute identity
            fused_depth: args.fused_depth,
            gpu_runtime_policy: gpu_runtime_policy_from_args(args),
            autoroute_gpu: args.autoroute_gpu && !args.no_autoroute_gpu,
            autoroute_calibration: args.autoroute_calibrate,
            regex_dfa_limit: args.regex_dfa_limit,
            source_limits: args.limits.to_source_limits(),
        }
    }
}

pub(crate) fn build_scanner_config(args: &ScanArgs) -> ScannerConfig {
    let input = ScannerConfigInput::from_scan_args(args);
    build_scanner_config_from_input(&input)
}

fn build_scanner_config_from_input(input: &ScannerConfigInput) -> ScannerConfig {
    // The preset (`--fast` / `--deep`) is a BASE, not a terminal state. It
    // seeds decode-depth / entropy / ml defaults; the per-flag overrides below
    // then layer on top. Pre-fix this function early-returned at the preset, so
    // `--deep --min-confidence 0.9` (or `--deep --entropy-threshold 5.0`, or any
    // `--known-prefixes` / keyword list) silently dropped the explicit override
    // - a coherence leak where "what the operator asked for" != "what ran". Only
    // `--no-decode` / `--no-entropy` are clap-conflicting with the presets
    // (`conflicts_with_all` on the `fast`/`deep` flags), so every other override
    // is a legitimate refinement of the preset base and must take effect.
    let mut config = if input.precision {
        ScannerConfig::high_precision()
    } else if input.fast {
        ScannerConfig::fast()
    } else if input.deep {
        ScannerConfig::thorough()
    } else {
        ScannerConfig::default()
    };

    if let Some(depth) = input.decode_depth {
        config.max_decode_depth = depth;
    }
    if input.no_decode {
        config.max_decode_depth = 0;
    }
    if let Some(size) = input.decode_size_limit {
        config.max_decode_bytes = size;
    }
    if let Some(conf) = input.min_confidence {
        // Under `--precision` the 0.85 floor is a MINIMUM the operator may
        // raise but not lower: `--precision --min-confidence 0.9` tightens to
        // 0.9, while `--precision --min-confidence 0.3` stays at 0.85 (the
        // documented "`--min-confidence` still overrides the floor on top"
        // contract is one-directional - it cannot punch a hole in the precision
        // bar). Every other mode lets the operator set the floor outright.
        config.min_confidence = if input.precision {
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
    if input.ml_threshold != ML_THRESHOLD_DEFAULT {
        config.min_confidence = config.min_confidence.max(input.ml_threshold);
    }
    // Keep the fixture opt-out coherent: skip both value suppressions and the
    // test/example path confidence penalty.
    config.penalize_test_paths = !input.no_suppress_test_fixtures;

    // `--no-entropy` conflicts with the presets at the clap layer, so under a
    // preset this is always `true` (entropy stays whatever the preset set). For
    // the no-preset path it honours the flag. Likewise `--no-decode` is preset-
    // conflicting; decode-depth above still applies for the no-preset path.
    if !(input.fast || input.deep || input.precision) {
        config.entropy_enabled = !input.no_entropy;
    }
    if let Some(threshold) = input.entropy_threshold {
        config.entropy_threshold = threshold;
    }
    if let Some(min_secret_len) = input.min_secret_len {
        config.min_secret_len = min_secret_len;
    }
    config.per_chunk_timeout_ms = input.per_chunk_timeout_ms;
    config.profile = input.profile;
    config.perf_trace = input.perf_trace;
    config.entropy_in_source_files = input.entropy_source_files;
    // Entropy candidates are scored through the MoE (model authoritative) by
    // default; `--no-entropy-ml-scoring` restores the legacy heuristic emit.
    // No-op unless entropy + ML are both on (gated in scan_entropy_fallback).
    config.entropy_ml_authoritative = !input.no_entropy_ml_scoring;
    // Keyword-anchored generic values use the relaxed entropy floor by default
    // (the keyword key is the evidence; precision carried by the MoE);
    // `--no-keyword-low-entropy` restores the high-entropy-only generic gate.
    // No-op unless the generic keyword bridge fires (scan_generic_assignments).
    // Composed with `&&` (not assigned) so the flag is one-directional: it can
    // only DISABLE the relaxed floor, never re-enable it under a preset that
    // turned it off (e.g. `--precision`, whose high_precision() base sets it
    // false). Mirrors the one-directional precision min_confidence contract.
    config.generic_keyword_low_entropy =
        config.generic_keyword_low_entropy && !input.no_keyword_low_entropy;
    config.scan_comments = input.scan_comments;
    config.ml_enabled = !input.fast && !input.no_ml;
    if let Some(weight) = input.ml_weight {
        config.ml_weight = weight;
    }
    config.unicode_normalization = !input.no_unicode_norm;
    if !input.known_prefixes.is_empty() {
        config.known_prefixes = input.known_prefixes.clone();
    }
    if !input.secret_keywords.is_empty() {
        config.secret_keywords = input.secret_keywords.clone();
    }
    if !input.test_keywords.is_empty() {
        config.test_keywords = input.test_keywords.clone();
    }
    if !input.placeholder_keywords.is_empty() {
        config.placeholder_keywords = input.placeholder_keywords.clone();
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

fn calibration_store_digest(calibration: &keyhog_core::Calibration) -> u64 {
    let mut hasher = crate::stable_hash::StableHasher::new("calibration-store-digest");
    let entries = calibration.entries();
    hasher.field_usize("entries.len", entries.len());
    for (id, counters) in entries {
        hasher.field_str("detector.id", &id);
        hasher.field_u64("detector.alpha", counters.alpha as u64);
        hasher.field_u64("detector.beta", counters.beta as u64);
    }
    hasher.finish_u64()
}

fn load_explicit_scan_calibration(
    path: Option<&Path>,
) -> Result<(
    Option<PathBuf>,
    Option<Arc<keyhog_core::Calibration>>,
    usize,
    u64,
)> {
    let Some(path) = path else {
        return Ok((None, None, 0, 0));
    };
    if path.is_dir() {
        anyhow::bail!(
            "calibration cache path '{}' is a directory. \
             Fix: pass a file path or remove --calibration-cache for a hermetic scan.",
            path.display()
        );
    }
    let calibration = match keyhog_core::Calibration::try_load(path) {
        Ok(Some(calibration)) => calibration,
        Ok(None) => {
            anyhow::bail!(
                "calibration cache '{}' does not exist. \
                 Fix: run `keyhog calibrate --cache '{}' --tp <detector-id>` or remove \
                 --calibration-cache for a hermetic scan.",
                path.display(),
                path.display()
            );
        }
        Err(error) => {
            anyhow::bail!(
                "{error}. Fix: repair or remove the cache, rerun `keyhog calibrate --cache '{}'`, \
                 or remove --calibration-cache for a hermetic scan.",
                path.display()
            );
        }
    };
    let entry_count = calibration.entries().len();
    let digest = calibration_store_digest(&calibration);
    Ok((
        Some(path.to_path_buf()),
        Some(Arc::new(calibration)),
        entry_count,
        digest,
    ))
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedAllowlistConfig {
    pub(crate) file: Option<PathBuf>,
    pub(crate) require_reason: bool,
    pub(crate) require_approved_by: bool,
    pub(crate) max_expires_days: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedReportPolicy {
    pub(crate) severity: Option<SeverityFilter>,
    pub(crate) dedup: CliDedupScope,
    pub(crate) verify: bool,
    pub(crate) lockdown: bool,
    pub(crate) show_secrets: bool,
    pub(crate) no_suppress_test_fixtures: bool,
    pub(crate) hide_client_safe: bool,
}

impl ResolvedReportPolicy {
    fn from_scan_args(args: &ScanArgs) -> Self {
        Self {
            severity: args.severity.clone(),
            dedup: args.dedup.clone(),
            verify: args.verify,
            lockdown: args.lockdown,
            show_secrets: args.show_secrets,
            no_suppress_test_fixtures: args.no_suppress_test_fixtures,
            hide_client_safe: args.hide_client_safe,
        }
    }
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
    /// Resolved explicit per-detector Bayesian calibration cache file. `None`
    /// means confidence scoring is hermetic and does not read disk state.
    pub(crate) calibration_cache_path: Option<PathBuf>,
    /// Number of detector counters loaded from the explicit calibration cache.
    pub(crate) calibration_entry_count: usize,
    /// Stable digest of the loaded calibration counters for config identity.
    pub(crate) calibration_digest: u64,
    /// Extra AWS canary/knockoff account IDs supplied by `.keyhog.toml`.
    pub(crate) aws_canary_accounts: Vec<String>,
    /// Explicit scanner route tuning supplied by `.keyhog.toml`.
    pub(crate) scanner_tuning: keyhog_scanner::ScannerTuningConfig,
    /// Resolved allowlist file and governance policy supplied by `.keyhog.toml`.
    pub(crate) allowlist: ResolvedAllowlistConfig,
    /// Resolved source byte/count limits applied while constructing sources.
    pub(crate) source_limits: keyhog_sources::SourceLimits,
    /// Resolved reporting/postprocess policy that can come from CLI or TOML.
    pub(crate) report: ResolvedReportPolicy,
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
    let runtime_input = ScanRuntimeInput::from_scan_args(args);
    let report = ResolvedReportPolicy::from_scan_args(args);
    configure_hyperscan_cache_dir(runtime_input.cache_dir.clone())?;
    let autoroute_cache_path = crate::autoroute_cache_path::resolve_autoroute_cache_path(
        runtime_input.autoroute_cache.as_deref(),
    )
    .map_err(anyhow::Error::msg)?;
    let backend_override = parse_backend_override(runtime_input.backend.as_deref())?;
    let scanner_tuning = outcome.scanner_tuning;
    let scanner_input = ScannerConfigInput::from_scan_args(args);
    let mut scanner = build_scanner_config_from_input(&scanner_input);
    let (calibration_cache_path, calibration_store, calibration_entry_count, calibration_digest) =
        load_explicit_scan_calibration(runtime_input.calibration_cache.as_deref())?;
    if let Some(calibration_store) = calibration_store {
        scanner = scanner.with_calibration(calibration_store);
    }
    // The post-scan floor is the SAME value the engine resolved - read it back
    // off the built config rather than re-deriving from `args`, so the two can
    // never drift. `ScannerConfig::from`/`sanitise` already clamped NaN/range.
    let min_confidence = scanner.min_confidence;
    let ml_enabled = scanner.ml_enabled;
    Ok(ResolvedScanConfig {
        backend_override,
        batch_pipeline: runtime_input.batch_pipeline,
        threads: runtime_input.threads,
        reader_threads: runtime_input.reader_threads,
        fused_batch: runtime_input.fused_batch,
        fused_depth: runtime_input.fused_depth,
        gpu_runtime_policy: runtime_input.gpu_runtime_policy,
        autoroute_gpu: runtime_input.autoroute_gpu,
        autoroute_calibration: runtime_input.autoroute_calibration,
        scanner,
        min_confidence,
        ml_enabled,
        detector_min_confidence: outcome.detector_min_confidence,
        disabled_detectors: outcome.disabled_detectors.into_iter().collect(),
        require_lockdown: outcome.require_lockdown,
        regex_dfa_limit: runtime_input.regex_dfa_limit,
        hyperscan_cache_dir: runtime_input.cache_dir,
        autoroute_cache_path,
        calibration_cache_path,
        calibration_entry_count,
        calibration_digest,
        aws_canary_accounts,
        scanner_tuning,
        allowlist: ResolvedAllowlistConfig {
            file: outcome.allowlist_file,
            require_reason: outcome.allowlist_require_reason,
            require_approved_by: outcome.allowlist_require_approved_by,
            max_expires_days: outcome.allowlist_max_expires_days,
        },
        source_limits: runtime_input.source_limits,
        report,
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
        calibration_cache_path: None,
        calibration_entry_count: 0,
        calibration_digest: 0,
        aws_canary_accounts: Vec::new(),
        scanner_tuning: keyhog_scanner::ScannerTuningConfig::default(),
        allowlist: ResolvedAllowlistConfig {
            file: None,
            require_reason: false,
            require_approved_by: false,
            max_expires_days: None,
        },
        source_limits: keyhog_sources::SourceLimits::default(),
        report: ResolvedReportPolicy {
            severity: None,
            dedup: CliDedupScope::Credential,
            verify: false,
            lockdown: false,
            show_secrets: false,
            no_suppress_test_fixtures: false,
            hide_client_safe: false,
        },
    }
}

#[doc(hidden)]
pub(crate) mod testing {
    use anyhow::Result;
    use keyhog_core::DetectorSpec;
    use std::path::Path;

    pub(crate) fn sanitise_thread_count(
        requested: usize,
        physical_cores: usize,
        source: &'static str,
    ) -> usize {
        super::runtime::testing::sanitise_thread_count(requested, physical_cores, source)
    }

    pub(crate) fn load_detectors_from_dir_with_cache(
        source_dir: &Path,
        cache_path: &Path,
    ) -> Result<Vec<DetectorSpec>> {
        super::detectors::testing::load_detectors_from_dir_with_cache(source_dir, cache_path)
    }
}
