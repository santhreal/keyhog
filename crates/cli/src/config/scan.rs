use super::limits::apply_limits_section;
use super::schema::{ConfigFile, ScanSection};
use crate::args::ScanArgs;
use crate::value_parsers::{
    parse_byte_size, parse_dedup_scope, parse_entropy_bpe_max_bytes_per_token,
    parse_entropy_threshold, parse_min_confidence, parse_ml_threshold, parse_ml_weight,
    parse_output_format, parse_severity_filter, DEDUP_SCOPE_ACCEPTED, OUTPUT_FORMAT_ACCEPTED,
    SEVERITY_ACCEPTED,
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

/// Validate a `.keyhog.toml` numeric knob by routing its value through the SAME
/// canonical CLI value_parser the corresponding flag uses (ONE-PLACE: each bound
/// lives in exactly one validator). Renders the TOML f64 to its string form, runs
/// the parser, and on rejection pushes a `field = value: <reason>` config error
/// (returning None so the caller leaves the arg at its default). This is the ONE
/// body for `min_confidence` / `ml_weight` / `ml_threshold` — the numeric knobs
/// settable on BOTH the flag AND the `[scan]`/top-level TOML; each wrapper supplies
/// only its parser. Without this routing, a config value the CLI fails closed on
/// (e.g. `min_confidence = 5.0`) was applied un-validated and silently broke
/// scanning (zero recall / distorted confidence) — a Law-10 silent failure.
fn parse_config_f64(
    errors: &mut Vec<String>,
    field: &str,
    value: f64,
    parse: impl Fn(&str) -> Result<f64, String>,
) -> Option<f64> {
    let rendered = value.to_string();
    match parse(&rendered) {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(super::invalid_config_value(field, &rendered, &error));
            None
        }
    }
}

fn parse_config_ml_threshold(errors: &mut Vec<String>, field: &str, threshold: f64) -> Option<f64> {
    parse_config_f64(errors, field, threshold, parse_ml_threshold)
}

pub(super) fn parse_config_min_confidence(
    errors: &mut Vec<String>,
    field: &str,
    confidence: f64,
) -> Option<f64> {
    parse_config_f64(errors, field, confidence, parse_min_confidence)
}

fn parse_config_ml_weight(errors: &mut Vec<String>, field: &str, weight: f64) -> Option<f64> {
    parse_config_f64(errors, field, weight, parse_ml_weight)
}

fn parse_config_entropy_bpe_bound(
    errors: &mut Vec<String>,
    field: &str,
    bound: f64,
) -> Option<f64> {
    parse_config_f64(errors, field, bound, parse_entropy_bpe_max_bytes_per_token)
}

fn parse_config_entropy_threshold(
    errors: &mut Vec<String>,
    field: &str,
    threshold: f64,
) -> Option<f64> {
    parse_config_f64(errors, field, threshold, parse_entropy_threshold)
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
    if config.entropy_bpe_max_bytes_per_token.is_some() {
        fields.push("entropy_bpe_max_bytes_per_token");
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
        .is_some_and(|scan| scan.entropy_threshold.is_some())
    {
        fields.push("[scan].entropy_threshold");
    }
    if config
        .scan
        .as_ref()
        .is_some_and(|scan| scan.min_secret_len.is_some())
    {
        fields.push("[scan].min_secret_len");
    }
    if config
        .scan
        .as_ref()
        .is_some_and(|scan| scan.entropy_bpe_max_bytes_per_token.is_some())
    {
        fields.push("[scan].entropy_bpe_max_bytes_per_token");
    }
    fields
}

/// Reject a scan knob defined through both its legacy flat alias and canonical
/// `[scan]` key. Choosing either value silently makes the other operator input
/// inert, and equality today can become a conflict when one side is edited.
/// CLI flags still override TOML; this gate concerns ambiguity inside one file.
pub(super) fn validate_scan_alias_conflicts(config: &ConfigFile, config_errors: &mut Vec<String>) {
    let Some(scan) = config.scan.as_ref() else {
        return;
    };
    macro_rules! reject_duplicate {
        ($flat:expr, $nested:expr, $name:literal) => {
            if $flat && $nested {
                config_errors.push(format!(
                    "- {0}: defined both as top-level `{0}` and canonical `[scan].{0}`; keep only `[scan].{0}`",
                    $name
                ));
            }
        };
    }
    reject_duplicate!(
        config.severity.is_some(),
        scan.severity.is_some(),
        "severity"
    );
    reject_duplicate!(config.format.is_some(), scan.format.is_some(), "format");
    reject_duplicate!(
        config.min_confidence.is_some(),
        scan.min_confidence.is_some(),
        "min_confidence"
    );
    reject_duplicate!(
        config.ml_threshold.is_some(),
        scan.ml_threshold.is_some(),
        "ml_threshold"
    );
    reject_duplicate!(config.threads.is_some(), scan.threads.is_some(), "threads");
    reject_duplicate!(
        config.reader_threads.is_some(),
        scan.reader_threads.is_some(),
        "reader_threads"
    );
    reject_duplicate!(
        config.fused_batch.is_some(),
        scan.fused_batch.is_some(),
        "fused_batch"
    );
    reject_duplicate!(
        config.fused_depth.is_some(),
        scan.fused_depth.is_some(),
        "fused_depth"
    );
    reject_duplicate!(
        config.per_chunk_timeout_ms.is_some(),
        scan.per_chunk_timeout_ms.is_some(),
        "per_chunk_timeout_ms"
    );
    reject_duplicate!(config.dedup.is_some(), scan.dedup.is_some(), "dedup");
    reject_duplicate!(
        config.incremental.is_some(),
        scan.incremental.is_some(),
        "incremental"
    );
    reject_duplicate!(
        config.incremental_cache.is_some(),
        scan.incremental_cache.is_some(),
        "incremental_cache"
    );
    reject_duplicate!(
        config.gpu_batch_input_limit.is_some(),
        scan.gpu_batch_input_limit.is_some(),
        "gpu_batch_input_limit"
    );
    reject_duplicate!(
        config.decode_depth.is_some(),
        scan.decode_depth.is_some(),
        "decode_depth"
    );
    reject_duplicate!(
        config.entropy_threshold.is_some(),
        scan.entropy_threshold.is_some(),
        "entropy_threshold"
    );
    reject_duplicate!(
        config.entropy_bpe_max_bytes_per_token.is_some(),
        scan.entropy_bpe_max_bytes_per_token.is_some(),
        "entropy_bpe_max_bytes_per_token"
    );
    reject_duplicate!(
        config.min_secret_len.is_some(),
        scan.min_secret_len.is_some(),
        "min_secret_len"
    );
    if config.exclude_paths.is_some() && scan.exclude.is_some() {
        config_errors.push(
            "- exclude: defined both as top-level `exclude_paths` and canonical `[scan].exclude`; keep only `[scan].exclude`"
                .to_string(),
        );
    }
}

/// Apply a `.keyhog.toml` positive-integer scan knob: reject `0` with a "use a
/// positive integer" config error, otherwise fill the CLI arg only when the
/// operator left it unset (CLI overrides TOML). ONE home for the reject-0 +
/// CLI-precedence guard that `threads` / `reader_threads` / `fused_batch` /
/// `fused_depth` / `per_chunk_timeout_ms` / `min_secret_len` all share on BOTH
/// the flat and `[scan]` config forms — `label` carries the `[scan].`-prefix
/// distinction, and the generic `T` covers the `usize` knobs plus the `u64`
/// `per_chunk_timeout_ms`. Before this the guard was pasted 12 times, which is
/// exactly how `threads` silently diverged from `reader_threads` (missing its
/// reject-0 check) until RECONCILE#14 — one owner makes that class impossible.
fn apply_positive_int_field<T: Copy + PartialEq + From<u8>>(
    config_errors: &mut Vec<String>,
    target: &mut Option<T>,
    label: &str,
    value: T,
) {
    if value == T::from(0u8) {
        config_errors.push(format!("- {label} = 0: use a positive integer"));
    } else if target.is_none() {
        *target = Some(value);
    }
}

pub(super) fn apply_scan_section(
    args: &mut ScanArgs,
    config_errors: &mut Vec<String>,
    scan: Option<ScanSection>,
) {
    // `[scan]` nested table - the surface the README documents as canonical.
    // Mirrors the flat top-level scalars and fills only fields still at their
    // default. `validate_scan_alias_conflicts` rejects a file that defines both
    // forms, so this fallback behavior applies only after an explicit CLI value.
    if let Some(scan) = scan {
        if let Some(ref s) = scan.severity {
            match parse_severity_filter(s) {
                Some(severity) => {
                    if args.severity.is_none() {
                        args.severity = Some(severity);
                    }
                }
                None => config_errors.push(super::invalid_config_value(
                    "[scan].severity",
                    s,
                    SEVERITY_ACCEPTED,
                )),
            }
        }
        if let Some(confidence) = scan.min_confidence {
            let parsed_confidence =
                parse_config_min_confidence(config_errors, "[scan].min_confidence", confidence);
            if args.min_confidence.is_none() {
                args.min_confidence = parsed_confidence;
            }
        }
        if let Some(threshold) = scan.ml_threshold {
            let parsed_threshold =
                parse_config_ml_threshold(config_errors, "[scan].ml_threshold", threshold);
            if args.ml_threshold.is_none() {
                args.ml_threshold = parsed_threshold;
            }
        }
        if let Some(threshold) = scan.entropy_threshold {
            let parsed_threshold = parse_config_entropy_threshold(
                config_errors,
                "[scan].entropy_threshold",
                threshold,
            );
            if args.entropy_threshold.is_none() {
                args.entropy_threshold = parsed_threshold;
            }
        }
        if let Some(bound) = scan.entropy_bpe_max_bytes_per_token {
            let parsed_bound = parse_config_entropy_bpe_bound(
                config_errors,
                "[scan].entropy_bpe_max_bytes_per_token",
                bound,
            );
            if args.entropy_bpe_max_bytes_per_token.is_none() {
                args.entropy_bpe_max_bytes_per_token = parsed_bound;
            }
        }
        if let Some(depth) = scan.decode_depth {
            let parsed_depth =
                parse_config_decode_depth(config_errors, "[scan].decode_depth", depth);
            if args.decode_depth.is_none() {
                args.decode_depth = parsed_depth;
            }
        }
        if let Some(min_secret_len) = scan.min_secret_len {
            apply_positive_int_field(
                config_errors,
                &mut args.min_secret_len,
                "[scan].min_secret_len",
                min_secret_len,
            );
        }
        if let Some(ref f) = scan.format {
            match parse_output_format(f) {
                Some(fmt) => {
                    if !args.format_cli_explicit
                        && matches!(args.format, crate::args::OutputFormat::Text)
                    {
                        args.format = fmt;
                    }
                }
                None => config_errors.push(super::invalid_config_value(
                    "[scan].format",
                    f,
                    OUTPUT_FORMAT_ACCEPTED,
                )),
            }
        }
        if args.exclude_paths.is_none() {
            args.exclude_paths = scan.exclude;
        }
        if let Some(threads) = scan.threads {
            apply_positive_int_field(config_errors, &mut args.threads, "[scan].threads", threads);
        }
        if let Some(threads) = scan.reader_threads {
            apply_positive_int_field(
                config_errors,
                &mut args.reader_threads,
                "[scan].reader_threads",
                threads,
            );
        }
        if let Some(batch) = scan.fused_batch {
            apply_positive_int_field(
                config_errors,
                &mut args.fused_batch,
                "[scan].fused_batch",
                batch,
            );
        }
        if let Some(depth) = scan.fused_depth {
            apply_positive_int_field(
                config_errors,
                &mut args.fused_depth,
                "[scan].fused_depth",
                depth,
            );
        }
        if let Some(timeout_ms) = scan.per_chunk_timeout_ms {
            apply_positive_int_field(
                config_errors,
                &mut args.per_chunk_timeout_ms,
                "[scan].per_chunk_timeout_ms",
                timeout_ms,
            );
        }
        if let Some(ref d) = scan.dedup {
            match parse_dedup_scope(d) {
                Some(scope) => {
                    if !args.dedup_cli_explicit
                        && matches!(args.dedup, crate::args::CliDedupScope::Credential)
                    {
                        args.dedup = scope;
                    }
                }
                None => config_errors.push(super::invalid_config_value(
                    "[scan].dedup",
                    d,
                    DEDUP_SCOPE_ACCEPTED,
                )),
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
        if let Some(ref limit) = scan.gpu_batch_input_limit {
            let parsed =
                parse_config_byte_size(config_errors, "[scan].gpu_batch_input_limit", limit);
            if args.gpu_batch_input_limit.is_none() {
                args.gpu_batch_input_limit = parsed;
            }
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
        if !args.detectors_cli_explicit && args.detectors == PathBuf::from("detectors") {
            args.detectors = PathBuf::from(detectors_str);
        }
    }

    if let Some(ref format_str) = config.format {
        match parse_output_format(format_str) {
            Some(fmt) => {
                // Only override if the user didn't set --format (defaults to Text).
                if !args.format_cli_explicit
                    && matches!(args.format, crate::args::OutputFormat::Text)
                {
                    args.format = fmt;
                }
            }
            None => config_errors.push(super::invalid_config_value(
                "format",
                format_str,
                OUTPUT_FORMAT_ACCEPTED,
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
                SEVERITY_ACCEPTED,
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
        let parsed = parse_config_min_confidence(config_errors, "min_confidence", min_conf);
        if args.min_confidence.is_none() {
            args.min_confidence = parsed;
        }
    }

    if let Some(threshold) = config.ml_threshold {
        let parsed_threshold = parse_config_ml_threshold(config_errors, "ml_threshold", threshold);
        if args.ml_threshold.is_none() {
            args.ml_threshold = parsed_threshold;
        }
    }

    if let Some(threads) = config.threads {
        apply_positive_int_field(config_errors, &mut args.threads, "threads", threads);
    }
    if let Some(threads) = config.reader_threads {
        apply_positive_int_field(
            config_errors,
            &mut args.reader_threads,
            "reader_threads",
            threads,
        );
    }
    if let Some(batch) = config.fused_batch {
        apply_positive_int_field(config_errors, &mut args.fused_batch, "fused_batch", batch);
    }
    if let Some(depth) = config.fused_depth {
        apply_positive_int_field(config_errors, &mut args.fused_depth, "fused_depth", depth);
    }
    if let Some(timeout_ms) = config.per_chunk_timeout_ms {
        apply_positive_int_field(
            config_errors,
            &mut args.per_chunk_timeout_ms,
            "per_chunk_timeout_ms",
            timeout_ms,
        );
    }

    if let Some(ref dedup_str) = config.dedup {
        match parse_dedup_scope(dedup_str) {
            Some(scope) => {
                // credential is the clap default
                if !args.dedup_cli_explicit
                    && matches!(args.dedup, crate::args::CliDedupScope::Credential)
                {
                    args.dedup = scope;
                }
            }
            None => config_errors.push(super::invalid_config_value(
                "dedup",
                dedup_str,
                DEDUP_SCOPE_ACCEPTED,
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
        let parsed_threshold =
            parse_config_entropy_threshold(config_errors, "entropy_threshold", entropy_threshold);
        if args.entropy_threshold.is_none() {
            args.entropy_threshold = parsed_threshold;
        }
    }

    if let Some(bpe_bound) = config.entropy_bpe_max_bytes_per_token {
        let parsed_bound = parse_config_entropy_bpe_bound(
            config_errors,
            "entropy_bpe_max_bytes_per_token",
            bpe_bound,
        );
        if args.entropy_bpe_max_bytes_per_token.is_none() {
            args.entropy_bpe_max_bytes_per_token = parsed_bound;
        }
    }

    if let Some(min_secret_len) = config.min_secret_len {
        apply_positive_int_field(
            config_errors,
            &mut args.min_secret_len,
            "min_secret_len",
            min_secret_len,
        );
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
        let parsed = parse_config_ml_weight(config_errors, "ml_weight", ml_weight);
        if args.ml_weight.is_none() {
            args.ml_weight = parsed;
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

    if let Some(ref limit_str) = config.gpu_batch_input_limit {
        let parsed_size = parse_config_byte_size(config_errors, "gpu_batch_input_limit", limit_str);
        if args.gpu_batch_input_limit.is_none() {
            if let Some(size) = parsed_size {
                args.gpu_batch_input_limit = Some(size);
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
