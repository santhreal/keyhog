use std::path::PathBuf;

/// On-disk `.keyhog.toml` configuration file that mirrors CLI arguments.
/// CLI flags always override values from the config file.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub(super) struct ConfigFile {
    /// Path to detector TOMLs directory.
    pub detectors: Option<String>,
    /// Minimum severity to report: info, low, medium, high, critical.
    pub severity: Option<String>,
    /// Output format: text, json, jsonl, sarif, csv, github-annotations, gitlab-sast, html, junit.
    pub format: Option<String>,
    /// Enable fast mode (pattern matching only).
    pub fast: Option<bool>,
    /// Enable deep mode (all features).
    pub deep: Option<bool>,
    /// Skip decode-through scanning.
    pub no_decode: Option<bool>,
    /// Skip entropy-based detection.
    pub no_entropy: Option<bool>,
    /// Minimum confidence score (0.0 - 1.0).
    pub min_confidence: Option<f64>,
    /// Number of parallel scanning threads.
    pub threads: Option<usize>,
    /// Dedicated filesystem reader threads.
    pub reader_threads: Option<usize>,
    /// Fused filesystem pipeline chunk batch size.
    pub fused_batch: Option<usize>,
    /// Fused filesystem pipeline channel depth.
    pub fused_depth: Option<usize>,
    /// Hard deadline per chunk scan in milliseconds.
    pub per_chunk_timeout_ms: Option<u64>,
    /// Deduplication scope: credential, file, none.
    pub dedup: Option<String>,
    /// Whether to verify discovered credentials.
    pub verify: Option<bool>,
    /// Verification timeout in seconds.
    pub timeout: Option<u64>,
    /// Max concurrent verification requests per service.
    pub rate: Option<usize>,
    /// Maximum git commits to traverse.
    pub max_commits: Option<usize>,
    /// Show full credentials (not redacted).
    pub show_secrets: Option<bool>,
    /// Enable incremental Merkle-cache scanning.
    pub incremental: Option<bool>,
    /// Override the incremental Merkle-cache file path.
    pub incremental_cache: Option<PathBuf>,
    /// Maximum depth for recursive decoding.
    pub decode_depth: Option<usize>,
    /// Maximum file size for decode-through scanning.
    pub decode_size_limit: Option<String>,
    /// Enable entropy scanning in source code files.
    pub entropy_source_files: Option<bool>,
    /// Entropy threshold in bits per byte.
    pub entropy_threshold: Option<f64>,
    /// Minimum credential length for entropy-fallback candidates.
    pub min_secret_len: Option<usize>,
    /// Disable Unicode normalization.
    pub no_unicode_norm: Option<bool>,
    /// Disable ML-based confidence scoring.
    pub no_ml: Option<bool>,
    /// Explicit paths or glob patterns to exclude from scanning.
    pub exclude_paths: Option<Vec<String>>,
    /// Maximum file size to scan.
    pub max_file_size: Option<String>,
    /// Per-regex lazy-DFA cache ceiling.
    pub regex_dfa_limit: Option<String>,
    /// ML weight for confidence scoring, 0.0-1.0.
    pub ml_weight: Option<f64>,
    /// Known secret prefixes used to boost confidence.
    pub known_prefixes: Option<Vec<String>>,
    /// Keywords indicating a secret context.
    pub secret_keywords: Option<Vec<String>>,
    /// Keywords indicating a test/mock context.
    pub test_keywords: Option<Vec<String>>,
    /// Keywords indicating a placeholder value.
    pub placeholder_keywords: Option<Vec<String>>,
    /// `[scan]` - runtime scan policy. Mirrors top-level scalar fields.
    pub scan: Option<ScanSection>,
    /// `[allowlist]` - `.keyhogignore` discovery + governance metadata.
    pub allowlist: Option<AllowlistSection>,
    /// `[detector.<id>]` - per-detector overrides keyed by detector_id.
    pub detector: Option<std::collections::HashMap<String, DetectorSection>>,
    /// `[lockdown]` - refuse to start unless explicit `--lockdown` flag.
    pub lockdown: Option<LockdownSection>,
    /// `[limits]` - source byte/count ceilings.
    pub limits: Option<LimitsSection>,
    /// `[system]` - host integration paths and other non-scan behavior.
    pub system: Option<SystemSection>,
    /// `[aws]` - AWS-specific offline safety metadata.
    pub aws: Option<AwsSection>,
    /// `[tuning]` - recall-equivalent scanner route tuning.
    pub tuning: Option<TuningSection>,
    /// Top-level compatibility alias for `[system].trusted_bin_dirs`.
    pub trusted_bin_dirs: Option<Vec<PathBuf>>,
}

/// `[scan]` nested table. Fields here map 1:1 to the flat top-level scalars.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub(super) struct ScanSection {
    pub severity: Option<String>,
    pub min_confidence: Option<f64>,
    pub decode_depth: Option<usize>,
    pub min_secret_len: Option<usize>,
    pub format: Option<String>,
    pub exclude: Option<Vec<String>>,
    pub threads: Option<usize>,
    pub reader_threads: Option<usize>,
    pub fused_batch: Option<usize>,
    pub fused_depth: Option<usize>,
    pub per_chunk_timeout_ms: Option<u64>,
    pub dedup: Option<String>,
    pub incremental: Option<bool>,
    pub incremental_cache: Option<PathBuf>,
}

/// `[allowlist]` nested table.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub(super) struct AllowlistSection {
    pub file: Option<String>,
    pub require_reason: Option<bool>,
    pub require_approved_by: Option<bool>,
    pub max_expires_days: Option<u64>,
}

/// `[detector.<id>]` per-detector override.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub(super) struct DetectorSection {
    pub enabled: Option<bool>,
    pub min_confidence: Option<f64>,
}

/// `[lockdown]` enforcement.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub(super) struct LockdownSection {
    pub require: Option<bool>,
}

/// `[limits]` source byte/count ceilings.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub(super) struct LimitsSection {
    pub stdin_bytes: Option<String>,
    pub web_response_bytes: Option<String>,
    pub s3_object_bytes: Option<String>,
    pub gcs_object_bytes: Option<String>,
    pub azure_blob_bytes: Option<String>,
    pub cloud_max_objects: Option<usize>,
    pub docker_tar_entry_bytes: Option<String>,
    pub docker_image_config_bytes: Option<String>,
    pub docker_tar_total_bytes: Option<String>,
    pub git_line_bytes: Option<String>,
    pub git_total_bytes: Option<String>,
    pub git_blob_bytes: Option<String>,
    pub git_chunks: Option<usize>,
    pub hosted_git_pages: Option<usize>,
    pub binary_read_bytes: Option<String>,
    pub binary_decompiled_bytes: Option<String>,
}

/// `[system]` host integration settings.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub(super) struct SystemSection {
    /// Absolute directories allowed by `keyhog_core::safe_bin` in addition to
    /// the compiled system defaults.
    pub trusted_bin_dirs: Option<Vec<PathBuf>>,
    /// Absolute Hyperscan compiled-database cache directory.
    pub cache_dir: Option<PathBuf>,
    /// Absolute autoroute calibration cache file, or `off` to disable.
    pub autoroute_cache: Option<String>,
    /// Absolute per-detector Bayesian calibration cache file for scan scoring.
    pub calibration_cache: Option<PathBuf>,
    /// Force the coalesced batch scan pipeline.
    pub batch_pipeline: Option<bool>,
    /// GPU runtime policy: auto, off, or required.
    pub gpu: Option<String>,
    /// Allow autoroute calibration to include GPU candidates.
    pub autoroute_gpu: Option<bool>,
}

/// `[aws]` offline AWS safety metadata.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub(super) struct AwsSection {
    /// Extra 12-digit AWS account IDs treated as canary-token issuers.
    pub canary_accounts: Option<Vec<String>>,
    /// Extra 12-digit AWS account IDs treated as off-brand canary issuers.
    pub knockoff_accounts: Option<Vec<String>>,
}

/// `[tuning]` scanner performance-route overrides.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub(super) struct TuningSection {
    pub fallback_hs: Option<bool>,
    pub hs_prefilter_max_len: Option<usize>,
    pub hs_shard_target: Option<usize>,
    pub fallback_anchor: Option<bool>,
    pub homoglyph_gate: Option<bool>,
    pub homoglyph_ascii_skip: Option<bool>,
    pub fallback_reverse: Option<bool>,
    pub prefilter_truncate: Option<bool>,
    pub fallback_prefix_gate: Option<bool>,
    pub decode_focus: Option<bool>,
    pub confirmed_suffix_gate: Option<bool>,
    pub no_candidate_gate: Option<bool>,
    pub fallback_localizer: Option<bool>,
    pub gpu_recall_floor: Option<bool>,
    pub gpu_moe_timeout_ms: Option<u64>,
}
