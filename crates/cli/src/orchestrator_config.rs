use crate::args::{CliDedupScope, ScanArgs};
use anyhow::Result;
use keyhog_scanner::ScannerConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod detectors;
mod effective;
mod policy;
mod runtime;
mod scanner;

pub(crate) use detectors::{
    auto_discover_detectors, detector_compile_failed, load_detectors_no_cache,
    load_detectors_or_embedded, load_detectors_with_cache,
};
pub(crate) use effective::{autoroute_config_digest, render_effective_config};
pub(crate) use policy::{ResolvedAllowlistConfig, ResolvedReportPolicy, ResolvedVerifyPolicy};
pub(crate) use runtime::{
    backend_override_label, configure_hyperscan_cache_dir, configure_threads, fused_depth_default,
    parse_backend_override, ScanRuntimeInput, FUSED_BATCH_DEFAULT, MAX_THREADS_CAP,
    ML_THRESHOLD_DEFAULT,
};
pub(crate) use scanner::build_scanner_config;
use scanner::{build_scanner_config_from_input, ScannerConfigInput};

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
    /// Resolved verifier transport/execution policy consumed by verifier
    /// postprocess without re-reading raw post-merge CLI args.
    pub(crate) verify: ResolvedVerifyPolicy,
}

/// Resolve the full scan configuration in one place: run the precedence merge
/// (compiled default -> `[scan]` table -> flat `ConfigFile` fields -> CLI flags)
/// via [`apply_config_file`], build the engine [`ScannerConfig`], and surface
/// the post-scan policy (global floor, ml gate, per-detector floors) so the live
/// worker consumes a resolved struct instead of re-reading raw args + a literal.
///
/// `args` is mutated in place by the config-file merge (CLI flags already win;
/// the merge only fills fields the operator left at their default), exactly as
/// the orchestrator's pre-existing `apply_config_file(&mut args)` call did.
/// Scanner, runtime, reporting, and verifier policy are captured into resolved
/// structs here so scan execution does not re-derive those decisions from raw
/// args.
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
    let verify = ResolvedVerifyPolicy::from_scan_args(args);
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
        verify,
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
        verify: ResolvedVerifyPolicy::disabled(),
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
