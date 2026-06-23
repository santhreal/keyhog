//! Configuration file handling for the KeyHog CLI.

use crate::args::ScanArgs;
use std::path::{Path, PathBuf};

mod limits;
mod scan;
mod schema;
mod sections;

use scan::{apply_scan_section, apply_top_level_scan_fields};
use schema::ConfigFile;
use sections::{
    apply_allowlist_section, apply_aws_section, apply_system_section, apply_tuning_section,
};

/// Compiled-in Tier-A per-detector confidence floors that ship inside the
/// binary, independent of any on-disk `.keyhog.toml`. This is the fix for the
/// "tuned != benched != shipped" leak: `[detector.<id>] min_confidence`
/// overrides used to exist ONLY in a user-authored `.keyhog.toml`, so the
/// bench and every default scan (which find no such file and short-circuit to
/// `ConfigOutcome::default()`) never exercised them. Floors listed here are
/// seeded into every `ConfigOutcome` regardless of whether a config file is
/// present, so the benched/default path runs the same per-detector tuning the
/// shipped binary carries. A user `.keyhog.toml` `[detector.<id>]
/// min_confidence` overrides the compiled value for that id (operator intent
/// wins per-detector); ids only listed here still apply on the no-file path.
///
/// Entries are `(detector_id, floor)`. Edit this table to raise the floor on a
/// specific noisy detector (e.g. loosened twilio / connection-string ones)
/// without requiring the operator to author a TOML; the change ships in the
/// binary and the bench picks it up automatically. Tier B (the detector
/// corpus) stays in `rules/`; this is the Tier-A scalar knob.
const SHIPPED_DETECTOR_FLOORS: &[(&str, f64)] = &[];

/// Compiled-in Tier-A detector disables that ship inside the binary, same
/// rationale as [`SHIPPED_DETECTOR_FLOORS`]: a detector listed here is dropped
/// from the loaded corpus on every path, including the no-config bench/default
/// path. A user `.keyhog.toml` `[detector.<id>] enabled = true` cannot
/// re-enable a compiled disable today (the merge is additive); keep this table
/// for detectors that must never fire by default.
const SHIPPED_DISABLED_DETECTORS: &[&str] = &[];

/// Build the baseline [`ConfigOutcome`] from the compiled-in Tier-A defaults.
/// Every return path of [`apply_config_file`] starts from this (not the empty
/// `ConfigOutcome::default()`), so the per-detector floors / disables that ship
/// in the binary reach the benched and default scans even when no
/// `.keyhog.toml` exists on disk.
fn shipped_config_outcome() -> ConfigOutcome {
    ConfigOutcome {
        disabled_detectors: SHIPPED_DISABLED_DETECTORS
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
        require_lockdown: false,
        detector_min_confidence: SHIPPED_DETECTOR_FLOORS
            .iter()
            .map(|(id, floor)| ((*id).to_string(), *floor))
            .collect(),
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

fn config_file_error(path: &Path, detail: impl std::fmt::Display, fix: &str) -> ConfigOutcome {
    let mut outcome = shipped_config_outcome();
    outcome
        .config_errors
        .push(format!("- {}: {detail}. Fix: {fix}", path.display()));
    outcome
}

pub(super) fn invalid_config_value(field: &str, value: &str, detail: &str) -> String {
    format!("- {field} = {value:?}: {detail}")
}

/// Search for `.keyhog.toml` starting from the scan root, walking up to the
/// filesystem root. Returns `None` when no config file is found.
pub(crate) fn find_config_file(start: Option<&std::path::Path>) -> Option<PathBuf> {
    let mut dir = start
        .and_then(|p| {
            if p.is_dir() {
                Some(p.to_path_buf())
            } else {
                p.parent().map(std::path::Path::to_path_buf)
            }
        })
        .or_else(|| std::env::current_dir().ok())?; // LAW10: optional env/cwd probe; absent => None (intended config/probe), recall-irrelevant

    loop {
        let candidate = dir.join(".keyhog.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

/// Outcome of merging `.keyhog.toml` into `ScanArgs`, beyond the in-place
/// `args` mutations: the things the caller must still act on.
///
/// Prefer [`crate::orchestrator_config::resolve_scan_config`] over calling
/// [`apply_config_file`] directly: it runs this same merge and then folds the
/// result into a single [`crate::orchestrator_config::ResolvedScanConfig`] - the
/// engine `ScannerConfig` PLUS the post-scan floors - so the live worker reads
/// one resolved struct instead of re-deriving the confidence floor from raw
/// `args` (the "tuned != benched != shipped" leak). `detector_min_confidence`
/// here is the source the resolved struct carries through to post-processing.
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
    /// Per-detector `[detector.<id>] min_confidence = <f>` overrides keyed by
    /// detector id. Applied in scan post-processing: a finding from detector
    /// `id` is dropped when its confidence is below this threshold, taking
    /// precedence over the global `--min-confidence`. Was parsed into
    /// `DetectorSection.min_confidence` and silently ignored before this
    /// wiring (the README documents it as active).
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

/// Load and merge a `.keyhog.toml` config file into the parsed `ScanArgs`.
/// CLI flags always take precedence over the config file.
///
/// Returns a [`ConfigOutcome`] the caller must act on: detector ids disabled
/// via `[detector.<id>] enabled = false` (dropped from the corpus) and whether
/// `[lockdown] require = true` demands `--lockdown`. Both are README-documented
/// but were parsed-and-silently-ignored before this wiring.
pub(crate) fn apply_config_file(args: &mut ScanArgs) -> ConfigOutcome {
    apply_config_file_impl(args, true)
}

/// Diagnostics-free variant for the daemon-routing PROBE in
/// [`crate::subcommands::scan`]'s `EffectivePolicy::resolve`, which applies the
/// config to a THROWAWAY clone of the args solely to read the resolved routing
/// knobs (min_confidence / show_secrets / severity). The real orchestrator merge
/// then runs [`apply_config_file`] and emits any read/parse warning exactly once.
/// Without this, the probe + the real call each printed the
/// "Failed to parse .keyhog.toml" warning, so a malformed config warned TWICE on
/// the daemon route (HUNT-2). Keep the emission on the real path; only the probe
/// is silenced.
pub(crate) fn apply_config_file_quiet(args: &mut ScanArgs) -> ConfigOutcome {
    apply_config_file_impl(args, false)
}

fn resolve_policy_outcome(config: &mut ConfigFile) -> ConfigOutcome {
    // `[lockdown] require = true` -> the caller refuses to run unless
    // `--lockdown` was passed (README: "refuse to run without --lockdown").
    let mut outcome = shipped_config_outcome();
    outcome.require_lockdown = config
        .lockdown
        .as_ref()
        .and_then(|l| l.require)
        .unwrap_or(false); // LAW10: empty/absent => documented numeric default, recall-safe

    // `[detector.<id>]` table: `enabled = false` drops the detector from the
    // loaded corpus after `load_detectors`; `min_confidence = <f>` becomes a
    // per-detector confidence floor applied in scan post-processing. Both keys
    // were README-documented; the confidence floor used to be parsed and
    // silently ignored (the disabled toggle was wired earlier). Drain the map
    // once into both outputs.
    //
    // Start from the compiled Tier-A defaults (`shipped_config_outcome`) so the
    // shipped floors/disables apply even when the `.keyhog.toml` does not
    // mention that detector, then layer the file on top: a file
    // `min_confidence` overrides the compiled floor for that id, and file
    // disables union with the compiled disables.
    if let Some(map) = config.detector.take() {
        for (id, section) in map {
            if section.enabled == Some(false) && !outcome.disabled_detectors.contains(&id) {
                outcome.disabled_detectors.push(id.clone());
            }
            if let Some(conf) = section.min_confidence {
                outcome.detector_min_confidence.insert(id, conf);
            }
        }
    }

    outcome
}

#[allow(clippy::collapsible_if, clippy::cmp_owned)]
fn apply_config_file_impl(args: &mut ScanArgs, emit_diagnostics: bool) -> ConfigOutcome {
    // `--no-config`: hermetic run on the compiled-in Tier-A shipped defaults.
    // Skip BOTH `.keyhog.toml` walk-up discovery AND any explicit `--config`
    // path (clap already rejects `--config` together with `--no-config`, so
    // honoring it here keeps the probe and the real merge consistent). This is
    // what the bench harness passes so the benched config is the shipped
    // default BY DESIGN, not by the accident of no config happening to be found
    // on the walk-up from a corpus that lives inside the repo tree (MC-07). The
    // shipped Tier-A floors/disables still apply — they ARE the default.
    if args.no_config {
        return shipped_config_outcome();
    }
    let config_path = args
        .config
        .clone()
        .or_else(|| find_config_file(args.path.as_deref()));

    let config_path = match config_path {
        Some(path) => path,
        // No `.keyhog.toml` on the walk-up path (the bench/default case): still
        // ship the compiled Tier-A floors/disables so tuned == benched ==
        // shipped, instead of the empty `ConfigOutcome::default()`.
        None => return shipped_config_outcome(),
    };

    let raw = match std::fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(error) => {
            if emit_diagnostics {
                tracing::warn!(
                    path = %config_path.display(),
                    "failed to read .keyhog.toml: {error}"
                );
            }
            return config_file_error(
                &config_path,
                format_args!("failed to read config file: {error}"),
                "make the file readable, pass a valid --config path, or run with --no-config",
            );
        }
    };

    let mut config: ConfigFile = match toml::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(error) => {
            // The daemon routing probe passes `emit_diagnostics = false` and
            // inspects `config_errors`; the real orchestrator merge turns the
            // same error into the single operator-visible CLI failure.
            if emit_diagnostics {
                tracing::warn!(
                    path = %config_path.display(),
                    "failed to parse .keyhog.toml: {error}"
                );
            }
            return config_file_error(
                &config_path,
                format_args!("failed to parse TOML: {error}"),
                "correct the TOML syntax or run with --no-config for a hermetic default scan",
            );
        }
    };

    tracing::debug!(path = %config_path.display(), "loaded .keyhog.toml");
    let mut config_errors = Vec::new();
    let mut trusted_bin_dirs = Vec::new();
    let mut aws_canary_accounts = Vec::new();
    let mut scanner_tuning = keyhog_scanner::ScannerTuningConfig::default();
    let mut allowlist_file = None;
    let mut allowlist_require_reason = false;
    let mut allowlist_require_approved_by = false;
    let mut allowlist_max_expires_days = None;

    apply_system_section(
        args,
        &mut config_errors,
        &mut trusted_bin_dirs,
        config.trusted_bin_dirs.as_deref(),
        config.system.as_ref(),
    );
    apply_aws_section(
        &mut config_errors,
        &mut aws_canary_accounts,
        config.aws.as_ref(),
    );
    apply_allowlist_section(
        &mut config_errors,
        &config_path,
        &mut allowlist_file,
        &mut allowlist_require_reason,
        &mut allowlist_require_approved_by,
        &mut allowlist_max_expires_days,
        config.allowlist.as_ref(),
    );
    apply_tuning_section(
        &mut config_errors,
        &mut scanner_tuning,
        config.tuning.as_ref(),
    );

    apply_top_level_scan_fields(args, &mut config_errors, &mut config);
    apply_scan_section(args, &mut config_errors, config.scan.take());

    let mut outcome = resolve_policy_outcome(&mut config);
    outcome.config_errors = config_errors;
    outcome.trusted_bin_dirs = trusted_bin_dirs;
    outcome.aws_canary_accounts = aws_canary_accounts;
    outcome.scanner_tuning = scanner_tuning;
    outcome.allowlist_file = allowlist_file;
    outcome.allowlist_require_reason = allowlist_require_reason;
    outcome.allowlist_require_approved_by = allowlist_require_approved_by;
    outcome.allowlist_max_expires_days = allowlist_max_expires_days;
    outcome
}
