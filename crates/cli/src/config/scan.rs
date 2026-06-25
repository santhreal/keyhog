use super::limits::apply_limits_section;
use super::schema::{ConfigFile, ScanSection};
use crate::args::ScanArgs;
use crate::value_parsers::{
    parse_byte_size, parse_dedup_scope, parse_ml_threshold, parse_output_format,
    parse_severity_filter,
};
use std::path::PathBuf;

/// Reject a user-supplied keyword list that contains an empty entry.
///
/// An empty keyword is meaningless as a match needle (it would match at every
/// byte offset) and, critically, reaches `slice::windows(0)` in the entropy
/// keyword/placeholder scan (`entropy::keywords::is_keyword_assignment_line`,
/// `entropy::plausibility::is_placeholder_ci`, `entropy::scanner`), which panics
/// with "size is zero" and crashes the whole scan. Fail closed at the config
/// boundary with a message that names the fix, rather than letting a
/// `.keyhog.toml` typo (`placeholder_keywords = [""]`) abort mid-scan with an
/// opaque panic. Returns `true` when the list is safe to apply.
fn keyword_list_is_nonempty(errors: &mut Vec<String>, field: &str, entries: &[String]) -> bool {
    if entries.iter().any(|entry| entry.is_empty()) {
        errors.push(format!(
            "- {field}: entries must not be empty; remove the empty \"\" item"
        ));
        return false;
    }
    true
}

pub(super) fn parse_config_byte_size(
    errors: &mut Vec<String>,
    field: &str,
    value: &str,
) -> Option<usize> {
    match parse_byte_size(value) {
        Ok(size) => Some(size),
        Err(error) => {
            errors.push(super::invalid_config_value(field, value, &error));
            None
        }
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

fn parse_config_ml_threshold(errors: &mut Vec<String>, field: &str, threshold: f64) -> Option<f64> {
    let rendered = threshold.to_string();
    match parse_ml_threshold(&rendered) {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(super::invalid_config_value(field, &rendered, &error));
            None
        }
    }
}

pub(super) fn validate_scan_preset_conflicts(
    args: &ScanArgs,
    config_errors: &mut Vec<String>,
    config: &ConfigFile,
) {
    // CLI presets are the highest-precedence layer. A lower-precedence config
    // key shadowed by a CLI preset is not a config-file contradiction; the CLI
    // did exactly what "CLI wins" promises. This validation rejects only same-
    // file TOML contradictions that would otherwise be accepted and then ignored
    // by the effective fast preset.
    if args.fast || args.deep || args.precision {
        return;
    }

    let toml_fast = config.fast == Some(true);
    let toml_deep = config.deep == Some(true);
    let toml_precision = config.precision == Some(true);
    if !(toml_fast || toml_deep || toml_precision) {
        return;
    }

    let presets = [
        ("fast", toml_fast),
        ("deep", toml_deep),
        ("precision", toml_precision),
    ];
    let selected: Vec<_> = presets
        .into_iter()
        .filter_map(|(name, enabled)| enabled.then_some(name))
        .collect();
    if selected.len() > 1 {
        config_errors.push(format!(
            "- {}: choose only one scan preset in .keyhog.toml",
            selected.join("/")
        ));
    }

    if !(toml_fast || toml_precision) {
        return;
    }
    let preset = if toml_fast {
        "fast = true"
    } else {
        "precision = true"
    };
    let mode = if toml_fast {
        "fast mode"
    } else {
        "precision mode"
    };

    for field in config_fast_noop_fields(config) {
        config_errors.push(format!(
            "- {field}: cannot be combined with {preset} because {mode} disables entropy/decode for that knob"
        ));
    }
}

fn config_fast_noop_fields(config: &ConfigFile) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if config.no_decode == Some(true) {
        fields.push("no_decode");
    }
    if config.no_entropy == Some(true) {
        fields.push("no_entropy");
    }
    if config.entropy_source_files == Some(true) {
        fields.push("entropy_source_files");
    }
    if config.entropy_threshold.is_some() {
        fields.push("entropy_threshold");
    }
    if config.min_secret_len.is_some() {
        fields.push("min_secret_len");
    }
    if config.generic_keyword_low_entropy == Some(false) {
        fields.push("generic_keyword_low_entropy = false");
    }
    if config
        .scan
        .as_ref()
        .is_some_and(|scan| scan.min_secret_len.is_some())
    {
        fields.push("[scan].min_secret_len");
    }
    fields
}

pub(super) fn apply_scan_section(
    args: &mut ScanArgs,
    config_errors: &mut Vec<String>,
    scan: Option<ScanSection>,
) {
    // `[scan]` nested table - the surface the README documents as canonical.
    // Mirrors the flat top-level scalars and fills only fields still at their
    // default (so the flat form wins if both are present, and a `[scan]`-only
    // config now actually takes effect instead of being silently dropped).
    if let Some(scan) = scan {
        if args.severity.is_none() {
            if let Some(ref s) = scan.severity {
                match parse_severity_filter(s) {
                    Some(severity) => args.severity = Some(severity),
                    None => config_errors.push(super::invalid_config_value(
                        "[scan].severity",
                        s,
                        "expected one of info, low, medium, high, critical",
                    )),
                }
            }
        } else if let Some(ref s) = scan.severity {
            if parse_severity_filter(s).is_none() {
                config_errors.push(super::invalid_config_value(
                    "[scan].severity",
                    s,
                    "expected one of info, low, medium, high, critical",
                ));
            }
        }
        if args.min_confidence.is_none() {
            args.min_confidence = scan.min_confidence;
        }
        if let Some(threshold) = scan.ml_threshold {
            let parsed_threshold =
                parse_config_ml_threshold(config_errors, "[scan].ml_threshold", threshold);
            if args.ml_threshold.is_none() {
                args.ml_threshold = parsed_threshold;
            }
        }
        if let Some(depth) = scan.decode_depth {
            let parsed_depth =
                parse_config_decode_depth(config_errors, "[scan].decode_depth", depth);
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
                    None => config_errors.push(super::invalid_config_value(
                        "[scan].format",
                        f,
                        "expected one of text, json, jsonl, sarif, csv, github-annotations, gitlab-sast, html, junit",
                    )),
                }
            }
        } else if let Some(ref f) = scan.format {
            if parse_output_format(f).is_none() {
                config_errors.push(super::invalid_config_value(
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
                    None => config_errors.push(super::invalid_config_value(
                        "[scan].dedup",
                        d,
                        "expected one of credential, file, none",
                    )),
                }
            }
        } else if let Some(ref d) = scan.dedup {
            if parse_dedup_scope(d).is_none() {
                config_errors.push(super::invalid_config_value(
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
}

pub(super) fn apply_top_level_scan_fields(
    args: &mut ScanArgs,
    config_errors: &mut Vec<String>,
    config: &mut ConfigFile,
) {
    // Apply config values only when no explicit CLI flag was given.
    let cli_preset_selected = args.fast || args.deep || args.precision;
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
            None => config_errors.push(super::invalid_config_value(
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
            None => config_errors.push(super::invalid_config_value(
                "severity",
                severity_str,
                "expected one of info, low, medium, high, critical",
            )),
        }
    }

    if let Some(no_decode) = config.no_decode {
        if !args.no_decode && !cli_preset_selected {
            args.no_decode = no_decode;
        }
    }

    if let Some(no_entropy) = config.no_entropy {
        if !args.no_entropy && !cli_preset_selected {
            args.no_entropy = no_entropy;
        }
    }

    if let Some(fast) = config.fast {
        if !args.fast && !args.deep && !args.precision {
            args.fast = fast;
        }
    }

    if let Some(deep) = config.deep {
        if !args.fast && !args.deep && !args.precision {
            args.deep = deep;
        }
    }

    if let Some(precision) = config.precision {
        if !args.fast && !args.deep && !args.precision {
            args.precision = precision;
        }
    }

    if let Some(min_conf) = config.min_confidence {
        if args.min_confidence.is_none() {
            args.min_confidence = Some(min_conf);
        }
    }

    if let Some(threshold) = config.ml_threshold {
        let parsed_threshold = parse_config_ml_threshold(config_errors, "ml_threshold", threshold);
        if args.ml_threshold.is_none() {
            args.ml_threshold = parsed_threshold;
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
            None => config_errors.push(super::invalid_config_value(
                "dedup",
                dedup_str,
                "expected one of credential, file, none",
            )),
        }
    }

    #[cfg(feature = "verify")]
    if let Some(verify) = config.verify {
        if !args.verify {
            args.verify = verify;
        }
    }
    #[cfg(not(feature = "verify"))]
    if config.verify.is_some() {
        config_errors.push(
            "- verify: this key requires the `verify` feature in this keyhog build".to_string(),
        );
    }

    #[cfg(feature = "verify")]
    if let Some(timeout) = config.timeout {
        if args.timeout.is_none() {
            args.timeout = Some(timeout);
        }
    }
    #[cfg(not(feature = "verify"))]
    if config.timeout.is_some() {
        config_errors.push(
            "- timeout: this key requires the `verify` feature in this keyhog build".to_string(),
        );
    }

    #[cfg(feature = "verify")]
    if let Some(rate) = config.rate {
        if args.rate.is_none() {
            args.rate = Some(rate);
        }
    }
    #[cfg(not(feature = "verify"))]
    if config.rate.is_some() {
        config_errors.push(
            "- rate: this key requires the `verify` feature in this keyhog build".to_string(),
        );
    }

    #[cfg(feature = "git")]
    if let Some(max_commits) = config.max_commits {
        if args.max_commits.is_none() {
            args.max_commits = Some(max_commits);
        }
    }
    #[cfg(not(feature = "git"))]
    if config.max_commits.is_some() {
        config_errors.push(
            "- max_commits: this key requires the `git` feature in this keyhog build".to_string(),
        );
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
        args.incremental_cache = config.incremental_cache.take();
    }

    if let Some(depth) = config.decode_depth {
        let parsed_depth = parse_config_decode_depth(config_errors, "decode_depth", depth);
        if args.decode_depth.is_none() {
            args.decode_depth = parsed_depth;
        }
    }

    if let Some(ref limit_str) = config.decode_size_limit {
        let parsed_size = parse_config_byte_size(config_errors, "decode_size_limit", limit_str);
        if args.decode_size_limit.is_none() {
            if let Some(size) = parsed_size {
                args.decode_size_limit = Some(size);
            }
        }
    }

    if let Some(entropy_source) = config.entropy_source_files {
        if !args.entropy_source_files {
            args.entropy_source_files = entropy_source;
        }
    }

    if let Some(entropy_threshold) = config.entropy_threshold {
        if args.entropy_threshold.is_none() {
            args.entropy_threshold = Some(entropy_threshold);
        }
    }

    if let Some(min_secret_len) = config.min_secret_len {
        if min_secret_len == 0 {
            config_errors.push("- min_secret_len = 0: use a positive integer".to_string());
        } else if args.min_secret_len.is_none() {
            args.min_secret_len = Some(min_secret_len);
        }
    }

    if config.generic_keyword_low_entropy == Some(false) && !args.no_keyword_low_entropy {
        args.no_keyword_low_entropy = true;
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
        let parsed_size = parse_config_byte_size(config_errors, "max_file_size", limit_str);
        if args.max_file_size.is_none() {
            if let Some(size) = parsed_size {
                args.max_file_size = Some(size);
            }
        }
    }

    if let Some(ref limit_str) = config.regex_dfa_limit {
        let parsed_size = parse_config_byte_size(config_errors, "regex_dfa_limit", limit_str);
        if args.regex_dfa_limit.is_none() {
            if let Some(size) = parsed_size {
                args.regex_dfa_limit = Some(size);
            }
        }
    }

    if let Some(limits) = config.limits.take() {
        apply_limits_section(args, config_errors, limits);
    }

    if let Some(paths) = config.exclude_paths.take() {
        if args.exclude_paths.is_none() {
            args.exclude_paths = Some(paths);
        }
    }

    if let Some(prefixes) = config.known_prefixes.take() {
        if keyword_list_is_nonempty(config_errors, "known_prefixes", &prefixes) {
            args.known_prefixes = prefixes;
        }
    }
    if let Some(keywords) = config.secret_keywords.take() {
        if keyword_list_is_nonempty(config_errors, "secret_keywords", &keywords) {
            args.secret_keywords = keywords;
        }
    }
    if let Some(keywords) = config.test_keywords.take() {
        if keyword_list_is_nonempty(config_errors, "test_keywords", &keywords) {
            args.test_keywords = keywords;
        }
    }
    if let Some(keywords) = config.placeholder_keywords.take() {
        if keyword_list_is_nonempty(config_errors, "placeholder_keywords", &keywords) {
            args.placeholder_keywords = keywords;
        }
    }
}
