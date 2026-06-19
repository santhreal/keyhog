//! Configuration file handling for the KeyHog CLI.

use crate::args::ScanArgs;
use crate::value_parsers::{
    parse_byte_size, parse_dedup_scope, parse_output_format, parse_severity_filter,
};
use std::path::{Path, PathBuf};

mod limits;
mod schema;

use limits::apply_limits_section;
use schema::ConfigFile;

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
    }
}

fn config_file_error(path: &Path, detail: impl std::fmt::Display, fix: &str) -> ConfigOutcome {
    let mut outcome = shipped_config_outcome();
    outcome
        .config_errors
        .push(format!("- {}: {detail}. Fix: {fix}", path.display()));
    outcome
}

fn invalid_config_value(field: &str, value: &str, detail: &str) -> String {
    format!("- {field} = {value:?}: {detail}")
}

fn parse_config_byte_size(errors: &mut Vec<String>, field: &str, value: &str) -> Option<usize> {
    match parse_byte_size(value) {
        Ok(size) => Some(size),
        Err(error) => {
            errors.push(invalid_config_value(field, value, &error));
            None
        }
    }
}

fn parse_gpu_runtime_policy(raw: &str) -> Option<keyhog_scanner::gpu::GpuRuntimePolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" => Some(keyhog_scanner::gpu::GpuRuntimePolicy::Auto),
        "off" | "disabled" | "disable" | "false" => {
            Some(keyhog_scanner::gpu::GpuRuntimePolicy::Disabled)
        }
        "required" | "require" | "on" | "true" => {
            Some(keyhog_scanner::gpu::GpuRuntimePolicy::Required)
        }
        _ => None,
    }
}

fn parse_config_decode_depth(errors: &mut Vec<String>, field: &str, depth: usize) -> Option<usize> {
    let limit = keyhog_core::max_decode_depth_limit();
    if (1..=limit).contains(&depth) {
        return Some(depth);
    }
    errors.push(format!(
        "- {field} = {depth}: decode depth must be between 1 and {limit}"
    ));
    None
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

    let config: ConfigFile = match toml::from_str(&raw) {
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

    let mut collect_trusted_bin_dirs = |field: &str, dirs: Option<Vec<PathBuf>>| {
        if let Some(dirs) = dirs {
            for dir in dirs {
                if dir.is_absolute() {
                    trusted_bin_dirs.push(dir);
                } else {
                    config_errors.push(format!(
                        "- {field}: trusted binary directory {} must be absolute",
                        dir.display()
                    ));
                }
            }
        }
    };
    collect_trusted_bin_dirs("trusted_bin_dirs", config.trusted_bin_dirs.clone());
    collect_trusted_bin_dirs(
        "[system].trusted_bin_dirs",
        config
            .system
            .as_ref()
            .and_then(|system| system.trusted_bin_dirs.clone()),
    );
    if let Some(cache_dir) = config
        .system
        .as_ref()
        .and_then(|system| system.cache_dir.clone())
    {
        if cache_dir.is_absolute() {
            if args.cache_dir.is_none() {
                args.cache_dir = Some(cache_dir);
            }
        } else {
            config_errors.push(format!(
                "- [system].cache_dir: Hyperscan cache directory {} must be absolute",
                cache_dir.display()
            ));
        }
    }
    if let Some(autoroute_cache) = config
        .system
        .as_ref()
        .and_then(|system| system.autoroute_cache.clone())
    {
        if args.autoroute_cache.is_none() {
            args.autoroute_cache = Some(autoroute_cache);
        }
    }
    if let Some(batch_pipeline) = config
        .system
        .as_ref()
        .and_then(|system| system.batch_pipeline)
    {
        if !args.batch_pipeline && !args.no_batch_pipeline {
            args.batch_pipeline = batch_pipeline;
        }
    }
    if let Some(gpu_policy) = config.system.as_ref().and_then(|system| system.gpu.clone()) {
        match parse_gpu_runtime_policy(&gpu_policy) {
            Some(keyhog_scanner::gpu::GpuRuntimePolicy::Disabled) => {
                if !args.no_gpu && !args.require_gpu {
                    args.no_gpu = true;
                }
            }
            Some(keyhog_scanner::gpu::GpuRuntimePolicy::Required) => {
                if !args.no_gpu && !args.require_gpu {
                    args.require_gpu = true;
                }
            }
            Some(keyhog_scanner::gpu::GpuRuntimePolicy::Auto) => {}
            None => config_errors.push(invalid_config_value(
                "[system].gpu",
                &gpu_policy,
                "expected auto, off, or required",
            )),
        }
    }
    if let Some(autoroute_gpu) = config
        .system
        .as_ref()
        .and_then(|system| system.autoroute_gpu)
    {
        if !args.autoroute_gpu && !args.no_autoroute_gpu {
            args.autoroute_gpu = autoroute_gpu;
        }
    }
    if let Some(aws) = config.aws.as_ref() {
        if let Some(accounts) = aws.canary_accounts.clone() {
            match keyhog_core::parse_canary_account_ids(accounts.iter().map(String::as_str)) {
                Ok(parsed) => aws_canary_accounts.extend(parsed),
                Err(error) => config_errors.push(format!("- [aws].canary_accounts: {error}")),
            }
        }
        if let Some(accounts) = aws.knockoff_accounts.clone() {
            match keyhog_core::parse_canary_account_ids(accounts.iter().map(String::as_str)) {
                Ok(parsed) => aws_canary_accounts.extend(parsed),
                Err(error) => config_errors.push(format!("- [aws].knockoff_accounts: {error}")),
            }
        }
    }
    if let Some(tuning) = config.tuning {
        scanner_tuning.phase2_hs = tuning.fallback_hs;
        scanner_tuning.hs_prefilter_max_len = tuning.hs_prefilter_max_len;
        if let Some(shard_target) = tuning.hs_shard_target {
            if shard_target == 0 {
                config_errors
                    .push("- [tuning].hs_shard_target: expected an integer >= 1".to_string());
            } else {
                scanner_tuning.hs_shard_target = Some(shard_target);
            }
        }
        scanner_tuning.phase2_anchor = tuning.fallback_anchor;
        scanner_tuning.homoglyph_gate = tuning.homoglyph_gate;
        scanner_tuning.homoglyph_ascii_skip = tuning.homoglyph_ascii_skip;
        scanner_tuning.fallback_reverse = tuning.fallback_reverse;
        scanner_tuning.prefilter_truncate = tuning.prefilter_truncate;
        scanner_tuning.fallback_prefix_gate = tuning.fallback_prefix_gate;
        scanner_tuning.decode_focus = tuning.decode_focus;
        scanner_tuning.confirmed_suffix_gate = tuning.confirmed_suffix_gate;
        scanner_tuning.no_candidate_gate = tuning.no_candidate_gate;
        scanner_tuning.fallback_localizer = tuning.fallback_localizer;
        scanner_tuning.gpu_recall_floor = tuning.gpu_recall_floor;
        if let Some(timeout_ms) = tuning.gpu_moe_timeout_ms {
            if timeout_ms == 0 {
                config_errors
                    .push("- [tuning].gpu_moe_timeout_ms: expected an integer >= 1".to_string());
            } else {
                scanner_tuning.gpu_moe_timeout_ms = Some(timeout_ms);
            }
        }
    }

    // Apply config values only when no explicit CLI flag was given.
    if let Some(ref detectors_str) = config.detectors {
        if args.detectors == PathBuf::from("detectors") {
            args.detectors = PathBuf::from(detectors_str);
        }
    }

    if let Some(ref format_str) = config.format {
        match parse_output_format(format_str) {
            Some(fmt) => {
                // Only override if the user didn't set --format (defaults to Text).
                if matches!(args.format, crate::args::OutputFormat::Text) {
                    args.format = fmt;
                }
            }
            None => config_errors.push(invalid_config_value(
                "format",
                format_str,
                "expected one of text, json, jsonl, sarif, csv, github-annotations, gitlab-sast, html, junit",
            )),
        }
    }

    if let Some(ref severity_str) = config.severity {
        match parse_severity_filter(severity_str) {
            Some(severity) => {
                if args.severity.is_none() {
                    args.severity = Some(severity);
                }
            }
            None => config_errors.push(invalid_config_value(
                "severity",
                severity_str,
                "expected one of info, low, medium, high, critical",
            )),
        }
    }

    if let Some(fast) = config.fast {
        if !args.fast && !args.deep {
            args.fast = fast;
        }
    }

    if let Some(deep) = config.deep {
        if !args.fast && !args.deep {
            args.deep = deep;
        }
    }

    if let Some(no_decode) = config.no_decode {
        if !args.no_decode {
            args.no_decode = no_decode;
        }
    }

    if let Some(_no_entropy) = config.no_entropy {
        if !args.no_entropy {
            args.no_entropy = _no_entropy;
        }
    }

    if let Some(min_conf) = config.min_confidence {
        if args.min_confidence.is_none() {
            args.min_confidence = Some(min_conf);
        }
    }

    if let Some(threads) = config.threads {
        if args.threads.is_none() {
            args.threads = Some(threads);
        }
    }
    if let Some(threads) = config.reader_threads {
        if threads == 0 {
            config_errors.push("- reader_threads = 0: use a positive integer".to_string());
        } else if args.reader_threads.is_none() {
            args.reader_threads = Some(threads);
        }
    }
    if let Some(batch) = config.fused_batch {
        if batch == 0 {
            config_errors.push("- fused_batch = 0: use a positive integer".to_string());
        } else if args.fused_batch.is_none() {
            args.fused_batch = Some(batch);
        }
    }
    if let Some(depth) = config.fused_depth {
        if depth == 0 {
            config_errors.push("- fused_depth = 0: use a positive integer".to_string());
        } else if args.fused_depth.is_none() {
            args.fused_depth = Some(depth);
        }
    }
    if let Some(timeout_ms) = config.per_chunk_timeout_ms {
        if timeout_ms == 0 {
            config_errors.push("- per_chunk_timeout_ms = 0: use a positive integer".to_string());
        } else if args.per_chunk_timeout_ms.is_none() {
            args.per_chunk_timeout_ms = Some(timeout_ms);
        }
    }

    if let Some(ref dedup_str) = config.dedup {
        match parse_dedup_scope(dedup_str) {
            Some(scope) => {
                // credential is the clap default
                if matches!(args.dedup, crate::args::CliDedupScope::Credential) {
                    args.dedup = scope;
                }
            }
            None => config_errors.push(invalid_config_value(
                "dedup",
                dedup_str,
                "expected one of credential, file, none",
            )),
        }
    }

    if let Some(_verify) = config.verify {
        #[cfg(feature = "verify")]
        if !args.verify {
            args.verify = _verify;
        }
    }

    if let Some(timeout) = config.timeout {
        if args.timeout == 5 {
            args.timeout = timeout;
        }
    }

    if let Some(rate) = config.rate {
        if args.rate == 5 {
            args.rate = rate;
        }
    }

    if let Some(_max_commits) = config.max_commits {
        #[cfg(feature = "git")]
        if args.max_commits == 1000 {
            args.max_commits = _max_commits;
        }
    }

    if let Some(show_secrets) = config.show_secrets {
        if !args.show_secrets {
            args.show_secrets = show_secrets;
        }
    }

    if let Some(incremental) = config.incremental {
        if !args.incremental {
            args.incremental = incremental;
        }
    }

    if args.incremental_cache.is_none() {
        args.incremental_cache = config.incremental_cache;
    }

    if let Some(depth) = config.decode_depth {
        let parsed_depth = parse_config_decode_depth(&mut config_errors, "decode_depth", depth);
        if args.decode_depth.is_none() {
            args.decode_depth = parsed_depth;
        }
    }

    if let Some(ref limit_str) = config.decode_size_limit {
        let parsed_size =
            parse_config_byte_size(&mut config_errors, "decode_size_limit", limit_str);
        if args.decode_size_limit.is_none() {
            if let Some(size) = parsed_size {
                args.decode_size_limit = Some(size);
            }
        }
    }

    if let Some(_entropy_source) = config.entropy_source_files {
        if !args.entropy_source_files {
            args.entropy_source_files = _entropy_source;
        }
    }

    if let Some(_entropy_threshold) = config.entropy_threshold {
        if args.entropy_threshold.is_none() {
            args.entropy_threshold = Some(_entropy_threshold);
        }
    }

    if let Some(min_secret_len) = config.min_secret_len {
        if min_secret_len == 0 {
            config_errors.push("- min_secret_len = 0: use a positive integer".to_string());
        } else if args.min_secret_len.is_none() {
            args.min_secret_len = Some(min_secret_len);
        }
    }

    if let Some(no_unicode_norm) = config.no_unicode_norm {
        if !args.no_unicode_norm {
            args.no_unicode_norm = no_unicode_norm;
        }
    }

    if let Some(no_ml) = config.no_ml {
        if !args.no_ml {
            args.no_ml = no_ml;
        }
    }

    if let Some(ml_weight) = config.ml_weight {
        if args.ml_weight.is_none() {
            args.ml_weight = Some(ml_weight);
        }
    }

    if let Some(ref limit_str) = config.max_file_size {
        let parsed_size = parse_config_byte_size(&mut config_errors, "max_file_size", limit_str);
        if args.max_file_size.is_none() {
            if let Some(size) = parsed_size {
                args.max_file_size = Some(size);
            }
        }
    }

    if let Some(ref limit_str) = config.regex_dfa_limit {
        let parsed_size = parse_config_byte_size(&mut config_errors, "regex_dfa_limit", limit_str);
        if args.regex_dfa_limit.is_none() {
            if let Some(size) = parsed_size {
                args.regex_dfa_limit = Some(size);
            }
        }
    }

    if let Some(limits) = config.limits {
        apply_limits_section(args, &mut config_errors, limits);
    }

    if let Some(paths) = config.exclude_paths {
        if args.exclude_paths.is_none() {
            args.exclude_paths = Some(paths);
        }
    }

    if let Some(prefixes) = config.known_prefixes {
        args.known_prefixes = prefixes;
    }
    if let Some(keywords) = config.secret_keywords {
        args.secret_keywords = keywords;
    }
    if let Some(keywords) = config.test_keywords {
        args.test_keywords = keywords;
    }
    if let Some(keywords) = config.placeholder_keywords {
        args.placeholder_keywords = keywords;
    }

    // `[scan]` nested table - the surface the README documents as canonical.
    // Mirrors the flat top-level scalars and fills only fields still at their
    // default (so the flat form wins if both are present, and a `[scan]`-only
    // config now actually takes effect instead of being silently dropped).
    if let Some(scan) = config.scan {
        if args.severity.is_none() {
            if let Some(ref s) = scan.severity {
                match parse_severity_filter(s) {
                    Some(severity) => args.severity = Some(severity),
                    None => config_errors.push(invalid_config_value(
                        "[scan].severity",
                        s,
                        "expected one of info, low, medium, high, critical",
                    )),
                }
            }
        } else if let Some(ref s) = scan.severity {
            if parse_severity_filter(s).is_none() {
                config_errors.push(invalid_config_value(
                    "[scan].severity",
                    s,
                    "expected one of info, low, medium, high, critical",
                ));
            }
        }
        if args.min_confidence.is_none() {
            args.min_confidence = scan.min_confidence;
        }
        if let Some(depth) = scan.decode_depth {
            let parsed_depth =
                parse_config_decode_depth(&mut config_errors, "[scan].decode_depth", depth);
            if args.decode_depth.is_none() {
                args.decode_depth = parsed_depth;
            }
        }
        if scan.min_secret_len == Some(0) {
            config_errors.push("- [scan].min_secret_len = 0: use a positive integer".to_string());
        } else if args.min_secret_len.is_none() {
            args.min_secret_len = scan.min_secret_len;
        }
        if matches!(args.format, crate::args::OutputFormat::Text) {
            if let Some(ref f) = scan.format {
                match parse_output_format(f) {
                    Some(fmt) => args.format = fmt,
                    None => config_errors.push(invalid_config_value(
                        "[scan].format",
                        f,
                        "expected one of text, json, jsonl, sarif, csv, github-annotations, gitlab-sast, html, junit",
                    )),
                }
            }
        } else if let Some(ref f) = scan.format {
            if parse_output_format(f).is_none() {
                config_errors.push(invalid_config_value(
                    "[scan].format",
                    f,
                    "expected one of text, json, jsonl, sarif, csv, github-annotations, gitlab-sast, html, junit",
                ));
            }
        }
        if args.exclude_paths.is_none() {
            args.exclude_paths = scan.exclude;
        }
        if args.threads.is_none() {
            args.threads = scan.threads;
        }
        if let Some(threads) = scan.reader_threads {
            if threads == 0 {
                config_errors
                    .push("- [scan].reader_threads = 0: use a positive integer".to_string());
            } else if args.reader_threads.is_none() {
                args.reader_threads = Some(threads);
            }
        }
        if let Some(batch) = scan.fused_batch {
            if batch == 0 {
                config_errors.push("- [scan].fused_batch = 0: use a positive integer".to_string());
            } else if args.fused_batch.is_none() {
                args.fused_batch = Some(batch);
            }
        }
        if let Some(depth) = scan.fused_depth {
            if depth == 0 {
                config_errors.push("- [scan].fused_depth = 0: use a positive integer".to_string());
            } else if args.fused_depth.is_none() {
                args.fused_depth = Some(depth);
            }
        }
        if let Some(timeout_ms) = scan.per_chunk_timeout_ms {
            if timeout_ms == 0 {
                config_errors
                    .push("- [scan].per_chunk_timeout_ms = 0: use a positive integer".to_string());
            } else if args.per_chunk_timeout_ms.is_none() {
                args.per_chunk_timeout_ms = Some(timeout_ms);
            }
        }
        if matches!(args.dedup, crate::args::CliDedupScope::Credential) {
            if let Some(ref d) = scan.dedup {
                match parse_dedup_scope(d) {
                    Some(scope) => args.dedup = scope,
                    None => config_errors.push(invalid_config_value(
                        "[scan].dedup",
                        d,
                        "expected one of credential, file, none",
                    )),
                }
            }
        } else if let Some(ref d) = scan.dedup {
            if parse_dedup_scope(d).is_none() {
                config_errors.push(invalid_config_value(
                    "[scan].dedup",
                    d,
                    "expected one of credential, file, none",
                ));
            }
        }
        if let Some(incremental) = scan.incremental {
            if !args.incremental {
                args.incremental = incremental;
            }
        }
        if args.incremental_cache.is_none() {
            args.incremental_cache = scan.incremental_cache;
        }
    }

    // `[lockdown] require = true` -> the caller refuses to run unless
    // `--lockdown` was passed (README: "refuse to run without --lockdown").
    let require_lockdown = config
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
    let baseline = shipped_config_outcome();
    let mut disabled_detectors = baseline.disabled_detectors;
    let mut detector_min_confidence = baseline.detector_min_confidence;
    if let Some(map) = config.detector {
        for (id, section) in map {
            if section.enabled == Some(false) && !disabled_detectors.contains(&id) {
                disabled_detectors.push(id.clone());
            }
            if let Some(conf) = section.min_confidence {
                detector_min_confidence.insert(id, conf);
            }
        }
    }

    ConfigOutcome {
        disabled_detectors,
        require_lockdown,
        detector_min_confidence,
        config_errors,
        trusted_bin_dirs,
        aws_canary_accounts,
        scanner_tuning,
    }
}

#[doc(hidden)]
pub(crate) mod testing {
    use std::path::{Path, PathBuf};

    pub(crate) fn apply_config_file_quiet(args: &mut crate::args::ScanArgs) {
        let _outcome = super::apply_config_file_quiet(args);
    }

    pub(crate) fn find_config_file(start: Option<&Path>) -> Option<PathBuf> {
        super::find_config_file(start)
    }
}
