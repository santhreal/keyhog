//! Configuration for KeyHog scanning and verification.
//!
//! Provides the [`ScanConfig`] struct used to control decoding depth,
//! entropy thresholds, deduplication strategy, and performance tuning.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::DedupScope;

/// Configuration for a scan run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Minimum confidence (0.0 to 1.0) required to report a finding.
    pub min_confidence: f64,
    /// Maximum recursive decoding depth (e.g. Base64(Hex(URL(secret)))).
    pub max_decode_depth: usize,
    /// Whether to enable Shannon entropy analysis for unknown high-entropy strings.
    pub entropy_enabled: bool,
    /// Whether to enable entropy analysis even in standard source code files.
    pub entropy_in_source_files: bool,
    /// Shannon entropy threshold (typical secrets are 4.5+).
    pub entropy_threshold: f64,
    /// Minimum length for entropy-based secret detection.
    pub min_secret_len: usize,
    /// Maximum file size to scan (bytes). Large files are skipped or sampled.
    pub max_file_size: u64,
    /// Deduplication strategy.
    pub dedup: DedupScope,

    /// Whether to enable ML-based probabilistic gating.
    pub ml_enabled: bool,
    /// Weight given to the ML score (0.0 to 1.0).
    pub ml_weight: f64,
    /// Whether to normalize Unicode characters before scanning.
    pub unicode_normalization: bool,
    /// Maximum bytes allowed from recursive decoding.
    pub decode_size_limit: usize,
    /// Maximum matches allowed per chunk to prevent OOM.
    pub max_matches_per_chunk: usize,

    /// List of common secret prefixes to prioritize.
    pub known_prefixes: Vec<String>,
    /// List of keywords that strongly indicate a secret.
    pub secret_keywords: Vec<String>,
    /// Keywords used in test environments.
    pub test_keywords: Vec<String>,
    /// Keywords for placeholders and documentation.
    pub placeholder_keywords: Vec<String>,
}

/// Limits for decoding to prevent infinite recursion or memory exhaustion.
pub const MAX_DECODE_DEPTH_LIMIT: usize = 16;

/// Errors returned while validating a scan configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("min_confidence must be between 0.0 and 1.0, found {0}")]
    InvalidConfidence(f64),
    #[error("max_decode_depth exceeds limit of {MAX_DECODE_DEPTH_LIMIT}, found {0}")]
    DepthTooHigh(usize),
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            // Raised from 0.3 → 0.5 (kimi-wave3 §4 LOW). The previous
            // 0.3 default let low-confidence generic-entropy matches
            // through, drowning real findings in noise. Detector
            // configs that want the looser bar can opt back in.
            min_confidence: 0.5,
            // Aligned with CLI / scanner defaults (`ScannerConfig` derives from this).
            max_decode_depth: 10,
            entropy_enabled: true,
            entropy_in_source_files: false,
            entropy_threshold: 4.5,
            min_secret_len: 20,
            max_file_size: 10 * 1024 * 1024, // 10 MB
            dedup: DedupScope::Credential,
            ml_enabled: true,
            ml_weight: 0.5,
            unicode_normalization: true,
            // Per-chunk decode-through ceiling (conservative vs multi‑MiB blobs).
            decode_size_limit: 512 * 1024,
            max_matches_per_chunk: 1000,
            known_prefixes: vec!["AKIA".into(), "ASIA".into(), "ghp_".into(), "sk_".into()],
            secret_keywords: vec![
                "password".into(),
                "passwd".into(),
                "pwd".into(),
                "secret".into(),
                "token".into(),
                "api_key".into(),
                "apikey".into(),
                "api-key".into(),
                "access_key".into(),
                "auth_token".into(),
                "auth_key".into(),
                "private_key".into(),
                "client_secret".into(),
                "encryption_key".into(),
                "signing_key".into(),
                "bearer".into(),
                "credential".into(),
                "license_key".into(),
            ],
            test_keywords: vec![
                "test".into(),
                "mock".into(),
                "fake".into(),
                "dummy".into(),
                "stub".into(),
                "fixture".into(),
                "example".into(),
                "sample".into(),
                "sandbox".into(),
                "staging".into(),
            ],
            placeholder_keywords: vec![
                "change_me".into(),
                "changeme".into(),
                "replace_me".into(),
                "todo".into(),
                "fixme".into(),
                "your_".into(),
                "insert_".into(),
                "put_your".into(),
                "fill_in".into(),
                "<your".into(),
            ],
        }
    }
}

impl ScanConfig {
    /// Fast configuration optimized for speed over exhaustive recall.
    pub fn fast() -> Self {
        Self {
            max_decode_depth: 2,
            entropy_enabled: false,
            ml_enabled: false,
            ..Default::default()
        }
    }

    /// Thorough configuration for deep penetration into encoded layers.
    pub fn thorough() -> Self {
        Self {
            max_decode_depth: 8,
            entropy_in_source_files: true,
            ml_enabled: true,
            ..Default::default()
        }
    }

    /// Maximum paranoia: deep decoding and aggressive entropy analysis.
    pub fn paranoid() -> Self {
        Self {
            max_decode_depth: MAX_DECODE_DEPTH_LIMIT,
            entropy_enabled: true,
            entropy_in_source_files: true,
            min_secret_len: 16,
            ml_enabled: true,
            ..Default::default()
        }
    }

    /// Validate the configuration parameters.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(0.0..=1.0).contains(&self.min_confidence) {
            return Err(ConfigError::InvalidConfidence(self.min_confidence));
        }
        if self.max_decode_depth > MAX_DECODE_DEPTH_LIMIT {
            return Err(ConfigError::DepthTooHigh(self.max_decode_depth));
        }
        Ok(())
    }
}

/// List of filenames that typically contain secrets (e.g. .env, config.json).
/// Return a list of filenames that typically contain secrets (e.g., .env, id_rsa).
pub fn secret_filenames() -> Vec<String> {
    vec![
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        ".env.test",
        "config.json",
        "config.yaml",
        "config.yml",
        "credentials.json",
        "secrets.json",
        "settings.json",
        "production.json",
        "development.json",
        "local.json",
        "appsettings.json",
        "web.config",
        "web.Debug.config",
        "web.Release.config",
        "Application.xml",
        "Settings.xml",
        "App.config",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "composer.json",
        "composer.lock",
        "pipfile",
        "pipfile.lock",
        "requirements.txt",
        "gemfile",
        "gemfile.lock",
        "cargo.toml",
        "cargo.lock",
        "go.mod",
        "go.sum",
        "docker-compose.yml",
        "docker-compose.yaml",
        "dockerfile",
        "kubernetes.yml",
        "kubernetes.yaml",
        "k8s.yml",
        "k8s.yaml",
        "deploy.yml",
        "deploy.yaml",
        "service.yml",
        "service.yaml",
        "configmap.yml",
        "configmap.yaml",
        "secret.yml",
        "secret.yaml",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
