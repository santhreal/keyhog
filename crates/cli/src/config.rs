//! Configuration file handling for the KeyHog CLI.

use crate::args::ScanArgs;
use std::path::PathBuf;

/// On-disk `.keyhog.toml` configuration file that mirrors CLI arguments.
/// CLI flags always override values from the config file.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct ConfigFile {
    /// Path to detector TOMLs directory.
    pub detectors: Option<String>,
    /// Minimum severity to report: info, low, medium, high, critical.
    pub severity: Option<String>,
    /// Output format: text, json, jsonl, sarif.
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
    /// Maximum depth for recursive decoding (1-10, default: 4).
    pub decode_depth: Option<usize>,
    /// Maximum file size for decode-through scanning (default: 64KB).
    pub decode_size_limit: Option<String>,
    /// Enable entropy scanning in source code files.
    pub entropy_source_files: Option<bool>,
    /// Entropy threshold in bits per byte (default: 4.5).
    pub entropy_threshold: Option<f64>,
    /// Disable Unicode normalization.
    pub no_unicode_norm: Option<bool>,
    /// Disable ML-based confidence scoring.
    pub no_ml: Option<bool>,
    /// Explicit paths or glob patterns to exclude from scanning.
    pub exclude_paths: Option<Vec<String>>,
    /// Maximum file size to scan (can be string like '1MB' or bytes).
    pub max_file_size: Option<String>,
    /// ML weight for confidence scoring, 0.0-1.0 (default: 0.6).
    pub ml_weight: Option<f64>,
    /// Known secret prefixes used to boost confidence.
    pub known_prefixes: Option<Vec<String>>,
    /// Keywords indicating a secret context (e.g. "api_key", "token").
    pub secret_keywords: Option<Vec<String>>,
    /// Keywords indicating a test/mock context (e.g. "test", "fake").
    pub test_keywords: Option<Vec<String>>,
    /// Keywords indicating a placeholder value (e.g. "change_me", "todo").
    pub placeholder_keywords: Option<Vec<String>>,
}

/// Search for `.keyhog.toml` starting from the scan root, walking up to the
/// filesystem root. Returns `None` when no config file is found.
pub fn find_config_file(start: Option<&std::path::Path>) -> Option<PathBuf> {
    let mut dir = start
        .and_then(|p| {
            if p.is_dir() {
                Some(p.to_path_buf())
            } else {
                p.parent().map(std::path::Path::to_path_buf)
            }
        })
        .or_else(|| std::env::current_dir().ok())?;

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
#[allow(clippy::collapsible_if, clippy::cmp_owned)]
pub fn apply_config_file(args: &mut ScanArgs) {
    let config_path = args
        .config
        .clone()
        .or_else(|| find_config_file(args.path.as_deref()));

    let config_path = match config_path {
        Some(path) => path,
        None => return,
    };

    let raw = match std::fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(error) => {
            tracing::warn!(
                path = %config_path.display(),
                "failed to read .keyhog.toml: {error}"
            );
            return;
        }
    };

    let config: ConfigFile = match toml::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!(
                "⚠️  WARNING: Failed to parse .keyhog.toml at {}: {}",
                config_path.display(),
                error
            );
            tracing::warn!(
                path = %config_path.display(),
                "failed to parse .keyhog.toml: {error}"
            );
            return;
        }
    };

    tracing::debug!(path = %config_path.display(), "loaded .keyhog.toml");

    // Apply config values only when no explicit CLI flag was given.
    if let Some(ref detectors_str) = config.detectors {
        if args.detectors == PathBuf::from("detectors") {
            args.detectors = PathBuf::from(detectors_str);
        }
    }

    if let Some(ref format_str) = config.format {
        // Shorthand: we only override if user didn't set --format (which defaults to Text)
        // This is a bit tricky with clap default_value, but we can check if it's the default.
        if matches!(args.format, crate::args::OutputFormat::Text) {
            match format_str.to_lowercase().as_str() {
                "json" => args.format = crate::args::OutputFormat::Json,
                "jsonl" => args.format = crate::args::OutputFormat::Jsonl,
                "sarif" => args.format = crate::args::OutputFormat::Sarif,
                "text" => args.format = crate::args::OutputFormat::Text,
                _ => {}
            }
        }
    }

    if let Some(ref severity_str) = config.severity {
        if args.severity.is_none() {
            match severity_str.to_lowercase().as_str() {
                "info" => args.severity = Some(crate::args::SeverityFilter::Info),
                "low" => args.severity = Some(crate::args::SeverityFilter::Low),
                "medium" => args.severity = Some(crate::args::SeverityFilter::Medium),
                "high" => args.severity = Some(crate::args::SeverityFilter::High),
                "critical" => args.severity = Some(crate::args::SeverityFilter::Critical),
                _ => {}
            }
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

    if let Some(ref dedup_str) = config.dedup {
        // credential is the clap default
        if matches!(args.dedup, crate::args::CliDedupScope::Credential) {
            match dedup_str.to_lowercase().as_str() {
                "credential" => args.dedup = crate::args::CliDedupScope::Credential,
                "file" => args.dedup = crate::args::CliDedupScope::File,
                "none" => args.dedup = crate::args::CliDedupScope::None,
                _ => {}
            }
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

    if let Some(depth) = config.decode_depth {
        if args.decode_depth.is_none() {
            args.decode_depth = Some(depth);
        }
    }

    if let Some(ref limit_str) = config.decode_size_limit {
        if args.decode_size_limit.is_none() {
            if let Ok(size) = crate::value_parsers::parse_byte_size(limit_str) {
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
        if args.max_file_size.is_none() {
            if let Ok(size) = crate::value_parsers::parse_byte_size(limit_str) {
                args.max_file_size = Some(size);
            }
        }
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
}
