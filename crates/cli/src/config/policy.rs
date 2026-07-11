use super::scan::parse_config_min_confidence;
use super::schema::ConfigFile;
use std::path::{Path, PathBuf};

/// Outcome of merging `.keyhog.toml` into `ScanArgs`, beyond the in-place
/// `args` mutations: the things the caller must still act on.
///
/// Prefer [`crate::orchestrator_config::resolve_scan_config`] over calling
/// [`super::apply_config_file`] directly: it runs this same merge and then
/// folds the result into a single
/// [`crate::orchestrator_config::ResolvedScanConfig`] - the engine
/// `ScannerConfig` plus the per-detector overrides - so the live worker reads one
/// resolved struct instead of re-deriving the confidence floor from raw `args`
/// (the "tuned != benched != shipped" leak). The orchestrator composes
/// `detector_min_confidence` into the active corpus before scanner compilation
/// and retains it for the matching post-scan check.
#[derive(Debug, Default)]
pub(crate) struct ConfigOutcome {
    /// Detector ids disabled via `[detector.<id>] enabled = false`; the caller
    /// drops these from the loaded corpus.
    pub disabled_detectors: Vec<String>,
    /// `[lockdown] require = true`: this repo's config DEMANDS lockdown mode.
    /// The caller must refuse to run unless `--lockdown` was passed. Documented
    /// in the README ("refuse to run without --lockdown") but, before this
    /// wiring, parsed and silently ignored - a security control that looked
    /// active but never enforced.
    pub require_lockdown: bool,
    /// Validated per-detector `[detector.<id>] min_confidence = <f>` overrides.
    /// The orchestrator writes these into the active detector specs before
    /// compilation and retains the same map for post-processing, so engine and
    /// reporter enforce one resolved floor.
    pub detector_min_confidence: std::collections::HashMap<String, f64>,
    /// Semantic config errors that TOML parsing alone cannot catch, such as
    /// invalid enum strings or byte-size strings. The real scan path fails
    /// closed on these; the quiet daemon-routing probe uses the same field to
    /// force routing back through the in-process path where the error is
    /// surfaced exactly once.
    pub config_errors: Vec<String>,
    /// Absolute extra binary directories trusted by `keyhog_core::safe_bin`.
    pub trusted_bin_dirs: Vec<PathBuf>,
    /// Extra AWS canary/knockoff account IDs supplied by `.keyhog.toml`.
    pub aws_canary_accounts: Vec<String>,
    /// Explicit scanner route tuning supplied by `.keyhog.toml`.
    pub scanner_tuning: keyhog_scanner::ScannerTuningConfig,
    /// Optional `.keyhogignore` path supplied by `[allowlist].file`.
    pub allowlist_file: Option<PathBuf>,
    /// `[allowlist].require_reason`: every active suppression needs a reason.
    pub allowlist_require_reason: bool,
    /// `[allowlist].require_approved_by`: every active suppression needs approval metadata.
    pub allowlist_require_approved_by: bool,
    /// `[allowlist].max_expires_days`: every active suppression needs a bounded expiry.
    pub allowlist_max_expires_days: Option<u64>,
}

/// Build the empty operator-policy baseline. Shipped per-detector behavior lives
/// only in each detector TOML; this outcome contains only repository/operator
/// overrides discovered from `.keyhog.toml`.
pub(super) fn base_config_outcome() -> ConfigOutcome {
    ConfigOutcome {
        disabled_detectors: Vec::new(),
        require_lockdown: false,
        detector_min_confidence: std::collections::HashMap::new(),
        config_errors: Vec::new(),
        trusted_bin_dirs: Vec::new(),
        aws_canary_accounts: Vec::new(),
        scanner_tuning: keyhog_scanner::ScannerTuningConfig::default(),
        allowlist_file: None,
        allowlist_require_reason: false,
        allowlist_require_approved_by: false,
        allowlist_max_expires_days: None,
    }
}

pub(super) fn config_file_error(
    path: &Path,
    detail: impl std::fmt::Display,
    fix: &str,
) -> ConfigOutcome {
    let mut outcome = base_config_outcome();
    outcome
        .config_errors
        .push(format!("- {}: {detail}. Fix: {fix}", path.display()));
    outcome
}

pub(super) fn resolve_policy_outcome(config: &mut ConfigFile) -> ConfigOutcome {
    // `[lockdown] require = true` -> the caller refuses to run unless
    // `--lockdown` was passed (README: "refuse to run without --lockdown").
    let mut outcome = base_config_outcome();
    outcome.require_lockdown = config
        .lockdown
        .as_ref()
        .and_then(|l| l.require)
        .unwrap_or(false); // LAW10: empty/absent => documented numeric default, recall-safe

    // `[detector.<id>]` table: `enabled = false` drops the detector from the
    // loaded corpus after `load_detectors`; `min_confidence = <f>` becomes a
    // per-detector confidence floor applied before scanner compilation and in
    // post-processing. Both keys
    // were README-documented; the confidence floor used to be parsed and
    // silently ignored (the disabled toggle was wired earlier). Drain the map
    // once into both outputs.
    //
    // Detector TOML owns shipped defaults. This map contains only operator
    // overrides/disables from the repository config and is composed with the
    // active detector specs before scanner compilation.
    if let Some(map) = config.detector.take() {
        for (id, section) in map {
            if section.enabled == Some(false) && !outcome.disabled_detectors.contains(&id) {
                outcome.disabled_detectors.push(id.clone());
            }
            if let Some(conf) = section.min_confidence {
                let field = format!("[detector.{id}].min_confidence");
                if let Some(conf) =
                    parse_config_min_confidence(&mut outcome.config_errors, &field, conf)
                {
                    outcome.detector_min_confidence.insert(id, conf);
                }
            }
        }
    }

    outcome
}
