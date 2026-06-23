use super::{backend_override_label, ResolvedScanConfig};
use crate::stable_hash::StableHasher;

/// Render the resolved scan config as a stable, human + machine readable block
/// for `keyhog config --effective`. It answers "what will actually run?" in one
/// place: the resolved engine config AND the post-scan floors, so a test (or an
/// operator) can assert that the tuned value, the benched value, and the shipped
/// value are the same number.
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
    out.push_str(&format!(
        "regex_dfa_limit = {}\n",
        resolved
            .regex_dfa_limit
            .map_or_else(|| "off".to_string(), |bytes| bytes.to_string())
    ));
    out.push_str(&format!(
        "max_file_size = {}\n",
        resolved
            .max_file_size
            .map_or_else(|| "off".to_string(), |bytes| bytes.to_string())
    ));
    out.push_str(&format!(
        "no_default_excludes = {}\n",
        resolved.no_default_excludes
    ));
    out.push_str(&format!(
        "exclude_paths = {}\n",
        resolved.exclude_paths.len()
    ));
    out.push_str(&format!("incremental = {}\n", resolved.incremental));
    let incremental_cache = resolved
        .incremental_cache_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<platform default>".to_string()); // LAW10: reporting-only label; actual cache path is resolved before use when incremental mode is enabled.
    out.push_str(&format!("incremental_cache = {incremental_cache}\n"));
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
        "limit_cloud_max_objects = {}\n",
        limits.cloud_max_objects
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
        "limit_hosted_git_pages = {}\n",
        limits.hosted_git_pages
    ));
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
    let calibration_cache_path = resolved
        .calibration_cache_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<disabled>".to_string()); // LAW10: reporting-only label for absent explicit calibration cache; scanner config carries None and does not read disk.
    out.push_str(&format!(
        "calibration_cache_path = {calibration_cache_path}\n"
    ));
    out.push_str(&format!(
        "calibration_entries = {}\n",
        resolved.calibration_entry_count
    ));
    out.push_str(&format!(
        "calibration_digest = {:016x}\n",
        resolved.calibration_digest
    ));
    out.push_str(&format!(
        "aws_canary_accounts = {}\n",
        resolved.aws_canary_accounts.len()
    ));
    let allowlist_file = match resolved.allowlist.file.as_ref() {
        Some(path) => path.display().to_string(),
        None => "<scan-root>/.keyhogignore".to_string(),
    };
    out.push_str(&format!("allowlist_file = {allowlist_file}\n"));
    out.push_str(&format!(
        "allowlist_require_reason = {}\n",
        resolved.allowlist.require_reason
    ));
    out.push_str(&format!(
        "allowlist_require_approved_by = {}\n",
        resolved.allowlist.require_approved_by
    ));
    let max_expires_days = match resolved.allowlist.max_expires_days {
        Some(days) => days.to_string(),
        None => "off".to_string(),
    };
    out.push_str(&format!(
        "allowlist_max_expires_days = {max_expires_days}\n"
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

/// Stable fingerprint for autoroute cache identity. It is computed from
/// the resolved config that actually reaches the engine/postprocess layer, so
/// `.keyhog.toml`, presets, CLI overrides, and host caps all invalidate routing
/// together when they change scan cost or candidate volume.
pub(crate) fn autoroute_config_digest(resolved: &ResolvedScanConfig) -> u64 {
    let mut h = StableHasher::new("autoroute-config-digest");
    let s = &resolved.scanner;
    h.field_f64_bits("scanner.min_confidence", s.min_confidence);
    h.field_bool("scanner.ml_enabled", s.ml_enabled);
    h.field_f64_bits("scanner.ml_weight", s.ml_weight);
    h.field_bool("scanner.entropy_enabled", s.entropy_enabled);
    h.field_bool(
        "scanner.entropy_ml_authoritative",
        s.entropy_ml_authoritative,
    );
    h.field_bool(
        "scanner.generic_keyword_low_entropy",
        s.generic_keyword_low_entropy,
    );
    h.field_f64_bits("scanner.entropy_threshold", s.entropy_threshold);
    h.field_bool("scanner.entropy_in_source_files", s.entropy_in_source_files);
    h.field_usize("scanner.max_decode_depth", s.max_decode_depth);
    h.field_usize("scanner.max_decode_bytes", s.max_decode_bytes);
    h.field_option_u64("scanner.per_chunk_timeout_ms", s.per_chunk_timeout_ms);
    h.field_usize("scanner.max_matches_per_chunk", s.max_matches_per_chunk);
    h.field_bool("scanner.scan_comments", s.scan_comments);
    h.field_bool("scanner.unicode_normalization", s.unicode_normalization);
    h.field_bool("scanner.penalize_test_paths", s.penalize_test_paths);
    h.field_usize(
        "scanner.multiline.max_join_lines",
        s.multiline.max_join_lines,
    );
    h.field_bool(
        "scanner.multiline.python_implicit",
        s.multiline.python_implicit,
    );
    h.field_bool(
        "scanner.multiline.backslash_continuation",
        s.multiline.backslash_continuation,
    );
    h.field_bool(
        "scanner.multiline.plus_concatenation",
        s.multiline.plus_concatenation,
    );
    h.field_bool(
        "scanner.multiline.template_literals",
        s.multiline.template_literals,
    );
    hash_strings(&mut h, "scanner.known_prefixes", &s.known_prefixes);
    hash_strings(&mut h, "scanner.secret_keywords", &s.secret_keywords);
    hash_strings(&mut h, "scanner.test_keywords", &s.test_keywords);
    hash_strings(
        &mut h,
        "scanner.placeholder_keywords",
        &s.placeholder_keywords,
    );
    h.field_f64_bits("resolved.min_confidence", resolved.min_confidence);
    h.field_bool("resolved.ml_enabled", resolved.ml_enabled);
    let mut floors: Vec<_> = resolved.detector_min_confidence.iter().collect();
    floors.sort_by(|a, b| a.0.cmp(b.0));
    h.field_usize("detector_min_confidence.len", floors.len());
    for (id, floor) in floors {
        h.field_str("detector_min_confidence.id", id);
        h.field_f64_bits("detector_min_confidence.floor", *floor);
    }
    let mut disabled: Vec<_> = resolved.disabled_detectors.iter().collect();
    disabled.sort();
    h.field_usize("disabled_detectors.len", disabled.len());
    for id in disabled {
        h.field_str("disabled_detectors.id", id);
    }
    h.field_bool("require_lockdown", resolved.require_lockdown);
    h.field_str(
        "backend_override",
        backend_override_label(resolved.backend_override),
    );
    h.field_bool("batch_pipeline", resolved.batch_pipeline);
    h.field_option_usize("threads", resolved.threads);
    h.field_option_usize("reader_threads", resolved.reader_threads);
    h.field_usize("fused_batch", resolved.fused_batch);
    h.field_option_usize("fused_depth", resolved.fused_depth);
    h.field_str(
        "gpu_runtime_policy",
        &resolved.gpu_runtime_policy.to_string(),
    );
    h.field_bool("autoroute_gpu", resolved.autoroute_gpu);
    h.field_option_usize("regex_dfa_limit", resolved.regex_dfa_limit);
    h.field_option_usize("source_policy.max_file_size", resolved.max_file_size);
    h.field_bool(
        "source_policy.no_default_excludes",
        resolved.no_default_excludes,
    );
    let mut exclude_paths = resolved.exclude_paths.clone();
    exclude_paths.sort();
    hash_strings(&mut h, "source_policy.exclude_paths", &exclude_paths);
    h.field_bool("source_policy.incremental", resolved.incremental);
    h.field_option_path(
        "source_policy.incremental_cache_path",
        resolved.incremental_cache_path.as_deref(),
    );
    h.field_option_path(
        "hyperscan_cache_dir",
        resolved.hyperscan_cache_dir.as_deref(),
    );
    h.field_option_path(
        "calibration_cache_path",
        resolved.calibration_cache_path.as_deref(),
    );
    h.field_u64("calibration_digest", resolved.calibration_digest);
    hash_strings(&mut h, "aws_canary_accounts", &resolved.aws_canary_accounts);
    hash_scanner_tuning(&mut h, &resolved.scanner_tuning);
    h.field_option_path("allowlist.file", resolved.allowlist.file.as_deref());
    h.field_bool(
        "allowlist.require_reason",
        resolved.allowlist.require_reason,
    );
    h.field_bool(
        "allowlist.require_approved_by",
        resolved.allowlist.require_approved_by,
    );
    h.field_option_u64(
        "allowlist.max_expires_days",
        resolved.allowlist.max_expires_days,
    );
    hash_source_limits(&mut h, resolved.source_limits);
    h.finish_u64()
}

fn hash_strings(h: &mut StableHasher, field: &str, strings: &[String]) {
    h.field_usize(&format!("{field}.len"), strings.len());
    for s in strings {
        h.field_str(field, s);
    }
}

fn hash_scanner_tuning(h: &mut StableHasher, tuning: &keyhog_scanner::ScannerTuningConfig) {
    let tuning = tuning.effective();
    h.field_bool("scanner_tuning.fallback_hs", tuning.fallback_hs);
    h.field_usize(
        "scanner_tuning.hs_prefilter_max_len",
        tuning.hs_prefilter_max_len,
    );
    h.field_usize("scanner_tuning.hs_shard_target", tuning.hs_shard_target);
    h.field_bool("scanner_tuning.fallback_anchor", tuning.fallback_anchor);
    h.field_bool("scanner_tuning.homoglyph_gate", tuning.homoglyph_gate);
    h.field_bool(
        "scanner_tuning.homoglyph_ascii_skip",
        tuning.homoglyph_ascii_skip,
    );
    h.field_bool("scanner_tuning.fallback_reverse", tuning.fallback_reverse);
    h.field_bool(
        "scanner_tuning.prefilter_truncate",
        tuning.prefilter_truncate,
    );
    h.field_bool(
        "scanner_tuning.fallback_prefix_gate",
        tuning.fallback_prefix_gate,
    );
    h.field_bool("scanner_tuning.decode_focus", tuning.decode_focus);
    h.field_bool(
        "scanner_tuning.confirmed_suffix_gate",
        tuning.confirmed_suffix_gate,
    );
    h.field_bool("scanner_tuning.no_candidate_gate", tuning.no_candidate_gate);
    h.field_bool(
        "scanner_tuning.fallback_localizer",
        tuning.fallback_localizer,
    );
    h.field_bool("scanner_tuning.gpu_recall_floor", tuning.gpu_recall_floor);
    h.field_u64(
        "scanner_tuning.gpu_moe_timeout_ms",
        tuning.gpu_moe_timeout_ms,
    );
}

fn hash_source_limits(h: &mut StableHasher, limits: keyhog_sources::SourceLimits) {
    h.field_usize("source_limits.stdin_bytes", limits.stdin_bytes);
    h.field_usize(
        "source_limits.web_response_bytes",
        limits.web_response_bytes,
    );
    h.field_u64("source_limits.s3_object_bytes", limits.s3_object_bytes);
    h.field_u64("source_limits.gcs_object_bytes", limits.gcs_object_bytes);
    h.field_u64("source_limits.azure_blob_bytes", limits.azure_blob_bytes);
    h.field_usize("source_limits.cloud_max_objects", limits.cloud_max_objects);
    h.field_u64(
        "source_limits.docker_tar_entry_bytes",
        limits.docker_tar_entry_bytes,
    );
    h.field_u64(
        "source_limits.docker_image_config_bytes",
        limits.docker_image_config_bytes,
    );
    h.field_u64(
        "source_limits.docker_tar_total_bytes",
        limits.docker_tar_total_bytes,
    );
    h.field_usize("source_limits.git_line_bytes", limits.git_line_bytes);
    h.field_usize("source_limits.git_total_bytes", limits.git_total_bytes);
    h.field_u64("source_limits.git_blob_bytes", limits.git_blob_bytes);
    h.field_usize("source_limits.git_chunk_count", limits.git_chunk_count);
    h.field_usize("source_limits.hosted_git_pages", limits.hosted_git_pages);
    h.field_usize("source_limits.binary_read_bytes", limits.binary_read_bytes);
    h.field_u64(
        "source_limits.binary_decompiled_bytes",
        limits.binary_decompiled_bytes,
    );
}
