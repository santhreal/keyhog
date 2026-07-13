//! Configuration file handling for the KeyHog CLI.

use crate::args::ScanArgs;
use std::path::PathBuf;

mod limits;
mod policy;
mod scan;
mod schema;
mod sections;

pub(crate) use policy::ConfigOutcome;
use policy::{base_config_outcome, config_file_error, resolve_policy_outcome};
use scan::{apply_scan_section, apply_top_level_scan_fields, validate_scan_preset_conflicts};
use schema::ConfigFile;
use sections::{
    apply_allowlist_section, apply_aws_section, apply_http_section, apply_system_section,
    apply_tuning_section,
};

const RETIRED_FLAT_SCAN_KEYS: &[&str] = &[
    "severity",
    "format",
    "min_confidence",
    "ml_threshold",
    "threads",
    "reader_threads",
    "fused_batch",
    "fused_depth",
    "per_chunk_timeout_ms",
    "dedup",
    "incremental",
    "incremental_cache",
    "gpu_batch_input_limit",
    "decode_depth",
    "entropy_threshold",
    "entropy_bpe_max_bytes_per_token",
    "min_secret_len",
    "exclude_paths",
];

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

#[allow(clippy::collapsible_if, clippy::cmp_owned)]
fn apply_config_file_impl(args: &mut ScanArgs, emit_diagnostics: bool) -> ConfigOutcome {
    // `--no-config`: hermetic run on the compiled-in Tier-A shipped defaults.
    // Skip BOTH `.keyhog.toml` walk-up discovery AND any explicit `--config`
    // path (clap already rejects `--config` together with `--no-config`, so
    // honoring it here keeps the probe and the real merge consistent). This is
    // what the bench harness passes so the benched config is the shipped
    // default BY DESIGN, not by the accident of no config happening to be found
    // on the walk-up from a corpus that lives inside the repo tree (MC-07). The
    // Detector-owned TOML policy remains embedded in the active corpus; only
    // repository/operator overrides are skipped.
    if args.no_config {
        return base_config_outcome();
    }
    let config_path = args
        .config
        .clone()
        .or_else(|| find_config_file(args.path.as_deref()));

    let config_path = match config_path {
        Some(path) => path,
        // No `.keyhog.toml` on the walk-up path (the bench/default case): use an
        // empty operator-policy outcome. Detector-owned TOML defaults are loaded
        // from the corpus by the orchestrator, so tuned == benched == shipped.
        None => return base_config_outcome(),
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
            let parsed_table = raw.parse::<toml::Table>().ok(); // LAW10: reporting-only best-effort parse for a more specific fix; the original TOML error still fails closed below
            let retired_key = parsed_table.as_ref().and_then(|table| {
                RETIRED_FLAT_SCAN_KEYS
                    .iter()
                    .copied()
                    .find(|key| table.contains_key(*key))
            });
            let fix = retired_key.map_or_else(
                || {
                    "correct the TOML syntax or run with --no-config for a hermetic default scan"
                        .to_string()
                },
                |key| {
                    let canonical = if key == "exclude_paths" { "exclude" } else { key };
                    format!(
                        "move top-level `{key}` to `[scan].{canonical}`; scan policy has one TOML owner"
                    )
                },
            );
            return config_file_error(
                &config_path,
                format_args!("failed to parse TOML: {error}"),
                &fix,
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
    validate_scan_preset_conflicts(args, &mut config_errors, &config);
    #[cfg(any(
        feature = "web",
        feature = "github",
        feature = "gitlab",
        feature = "bitbucket",
        feature = "s3",
        feature = "gcs",
        feature = "azure",
        feature = "verify"
    ))]
    apply_http_section(args, config.http.as_ref());
    #[cfg(not(any(
        feature = "web",
        feature = "github",
        feature = "gitlab",
        feature = "bitbucket",
        feature = "s3",
        feature = "gcs",
        feature = "azure",
        feature = "verify"
    )))]
    apply_http_section(args, &mut config_errors, config.http.as_ref());

    apply_top_level_scan_fields(args, &mut config_errors, &mut config);
    apply_scan_section(args, &mut config_errors, config.scan.take());

    let mut outcome = resolve_policy_outcome(&mut config);
    // Policy resolution may add errors for `[detector.<id>]` values. Preserve
    // them after the earlier scan/system validation errors instead of replacing
    // either set.
    config_errors.append(&mut outcome.config_errors);
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
