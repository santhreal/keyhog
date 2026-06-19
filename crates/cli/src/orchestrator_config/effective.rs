use super::{backend_override_label, ResolvedScanConfig};

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
    out.push_str(&format!(
        "aws_canary_accounts = {}\n",
        resolved.aws_canary_accounts.len()
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

/// Stable-enough fingerprint for autoroute cache identity. It is computed from
/// the resolved config that actually reaches the engine/postprocess layer, so
/// `.keyhog.toml`, presets, CLI overrides, and host caps all invalidate routing
/// together when they change scan cost or candidate volume.
pub(crate) fn autoroute_config_digest(resolved: &ResolvedScanConfig) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let s = &resolved.scanner;
    s.min_confidence.to_bits().hash(&mut h);
    s.ml_enabled.hash(&mut h);
    s.ml_weight.to_bits().hash(&mut h);
    s.entropy_enabled.hash(&mut h);
    s.entropy_ml_authoritative.hash(&mut h);
    s.generic_keyword_low_entropy.hash(&mut h);
    s.entropy_threshold.to_bits().hash(&mut h);
    s.entropy_in_source_files.hash(&mut h);
    s.max_decode_depth.hash(&mut h);
    s.max_decode_bytes.hash(&mut h);
    s.per_chunk_timeout_ms.hash(&mut h);
    s.max_matches_per_chunk.hash(&mut h);
    s.scan_comments.hash(&mut h);
    s.unicode_normalization.hash(&mut h);
    s.penalize_test_paths.hash(&mut h);
    s.multiline.max_join_lines.hash(&mut h);
    s.multiline.python_implicit.hash(&mut h);
    s.multiline.backslash_continuation.hash(&mut h);
    s.multiline.plus_concatenation.hash(&mut h);
    s.multiline.template_literals.hash(&mut h);
    hash_strings(&s.known_prefixes, &mut h);
    hash_strings(&s.secret_keywords, &mut h);
    hash_strings(&s.test_keywords, &mut h);
    hash_strings(&s.placeholder_keywords, &mut h);
    resolved.min_confidence.to_bits().hash(&mut h);
    resolved.ml_enabled.hash(&mut h);
    let mut floors: Vec<_> = resolved.detector_min_confidence.iter().collect();
    floors.sort_by(|a, b| a.0.cmp(b.0));
    for (id, floor) in floors {
        id.hash(&mut h);
        floor.to_bits().hash(&mut h);
    }
    let mut disabled: Vec<_> = resolved.disabled_detectors.iter().collect();
    disabled.sort();
    for id in disabled {
        id.hash(&mut h);
    }
    resolved.require_lockdown.hash(&mut h);
    backend_override_label(resolved.backend_override).hash(&mut h);
    resolved.batch_pipeline.hash(&mut h);
    resolved.threads.hash(&mut h);
    resolved.reader_threads.hash(&mut h);
    resolved.fused_batch.hash(&mut h);
    resolved.fused_depth.hash(&mut h);
    resolved.gpu_runtime_policy.hash(&mut h);
    resolved.autoroute_gpu.hash(&mut h);
    resolved.regex_dfa_limit.hash(&mut h);
    resolved.hyperscan_cache_dir.hash(&mut h);
    resolved.aws_canary_accounts.hash(&mut h);
    resolved.scanner_tuning.hash(&mut h);
    resolved.source_limits.hash(&mut h);
    h.finish()
}

fn hash_strings(strings: &[String], h: &mut impl std::hash::Hasher) {
    use std::hash::Hash;
    strings.len().hash(h);
    for s in strings {
        s.hash(h);
    }
}
