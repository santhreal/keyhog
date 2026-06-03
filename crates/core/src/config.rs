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
    /// When the entropy fallback fires, score its candidates through the MoE
    /// with the model AUTHORITATIVE (the entropy magnitude is NOT a confidence
    /// floor) instead of emitting the bare entropy heuristic. Default on: on the
    /// real-distribution-trained model this is a recall-safe precision win — the
    /// model scores real high-entropy secrets high and structured non-secrets
    /// (FQDNs, git SHAs, base64 blobs) low, so FPs fall below the report floor
    /// while genuine recall is preserved. Opt out with `--no-entropy-ml-scoring`.
    /// No-op when `entropy_enabled` or `ml_enabled` is false.
    #[serde(default = "default_entropy_ml_authoritative")]
    pub entropy_ml_authoritative: bool,
    /// When the generic keyword bridge (`PASSWORD=`, `*_PASS=`, `secret:`,
    /// `api_key=` ...) extracts a value, admit it on a far lower entropy floor
    /// (the `generic-keyword-secret` base, ~1.5 bits) than the bare
    /// `generic-secret` path (2.8/3.2/3.5). The credential KEYWORD in the key is
    /// the evidence; precision is carried by the MoE + shape filters, not by
    /// entropy. Default on: this is what lets keyhog surface the real-world
    /// low-entropy credentials (config passwords, `*_PASS=` values) that pin
    /// CredData recall near zero when gated on entropy alone. Opt out with
    /// `--no-keyword-low-entropy` to restore the high-entropy-only generic gate.
    /// No-op unless the keyword bridge fires.
    #[serde(default = "default_generic_keyword_low_entropy")]
    pub generic_keyword_low_entropy: bool,
    /// Shannon entropy threshold (typical secrets are 4.5+).
    pub entropy_threshold: f64,
    /// Minimum length for entropy-based secret detection.
    ///
    /// NOTE: not yet read by the live scan. `From<ScanConfig> for
    /// ScannerConfig` does not carry this field; the entropy length
    /// gate currently uses the engine's own length constants. Setting
    /// it in a deserialized config is a no-op until a reader is wired
    /// in. See the `From` impl on `ScannerConfig` for the canonical
    /// list of carried vs uncarried fields.
    pub min_secret_len: usize,
    /// Maximum file size to scan (bytes). Large files are skipped or sampled.
    ///
    /// NOTE: not read here on the live path. The effective cap is set
    /// at the source walker (`FilesystemSource::with_max_file_size`,
    /// fed from `ScanArgs.max_file_size`); this field is retained for
    /// the canonical config surface but is not carried into
    /// `ScannerConfig`.
    pub max_file_size: u64,
    /// Deduplication strategy.
    ///
    /// NOTE: not read here on the live path. The effective scope comes
    /// from `ScanArgs.dedup` and is applied by the verifier via
    /// `DedupScope`; this field is not carried into `ScannerConfig`.
    pub dedup: DedupScope,

    /// Whether to enable ML-based probabilistic gating.
    pub ml_enabled: bool,
    /// Weight given to the ML score (0.0 to 1.0).
    pub ml_weight: f64,
    /// Whether to normalize Unicode characters before scanning.
    pub unicode_normalization: bool,
    /// Whether to validate decoded strings (e.g. that decoded base64 is
    /// UTF-8) before recursing into them.
    pub validate_decode: bool,
    /// Maximum bytes allowed from recursive decoding. Same field name on
    /// `ScannerConfig` so `From<ScanConfig>` is a 1:1 carry, not a rename.
    pub max_decode_bytes: usize,
    /// Maximum matches allowed per chunk to prevent OOM.
    pub max_matches_per_chunk: usize,

    /// When `true`, credentials inside source-code comments
    /// (//, #, /* */, <!-- -->) get the same confidence treatment as
    /// credentials in regular code. Default `false` - comment context
    /// downgrades confidence on the theory that examples are the
    /// common case. CLI exposes this as `--scan-comments`; opt-in
    /// because the rate of EXAMPLE secrets pasted into doc comments
    /// vastly outweighs the rate of real ones.
    #[serde(default)]
    pub scan_comments: bool,

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

/// Serde default for [`ScanConfig::entropy_ml_authoritative`]: a config
/// deserialized from a TOML that predates the field gets the shipped default
/// (on) rather than `bool`'s `false`, so old configs don't silently disable it.
fn default_entropy_ml_authoritative() -> bool {
    true
}

/// Serde default for [`ScanConfig::generic_keyword_low_entropy`]: configs that
/// predate the field get the shipped default (on) rather than `bool`'s `false`,
/// so old TOMLs don't silently fall back to the high-entropy-only generic gate.
fn default_generic_keyword_low_entropy() -> bool {
    true
}

/// Errors returned while validating a scan configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// `min_confidence` was outside the closed unit interval `[0.0, 1.0]`.
    #[error("min_confidence must be between 0.0 and 1.0, found {0}")]
    InvalidConfidence(f64),
    /// `max_decode_depth` exceeded the safety ceiling
    /// [`MAX_DECODE_DEPTH_LIMIT`].
    #[error("max_decode_depth exceeds limit of {MAX_DECODE_DEPTH_LIMIT}, found {0}")]
    DepthTooHigh(usize),
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            // Bench-tuned floor (SecretBench mirror grid-sweep 2026-05-30):
            // 0.40 maximises F1 (0.8642, P=0.984, FP=37) and is the precision
            // sweet spot. 0.30 admits a low-confidence FP band (FP 174); 0.50
            // is WORSE on both axes (the floor is non-monotonic in FP - see
            // the scan-time/ML entanglement bug tracked in backlog DET-08).
            // This is the canonical tuned == benched == shipped floor; the
            // post-scan gate (orchestrator/postprocess.rs) and the scan-time
            // generic gate (engine/fallback_generic.rs) both resolve to it.
            min_confidence: 0.40,
            // Aligned with CLI / scanner defaults (`ScannerConfig` derives from this).
            max_decode_depth: 10,
            entropy_enabled: true,
            entropy_in_source_files: false,
            entropy_ml_authoritative: true,
            generic_keyword_low_entropy: true,
            entropy_threshold: 4.5,
            min_secret_len: 20,
            max_file_size: 10 * 1024 * 1024, // 10 MB
            dedup: DedupScope::Credential,
            ml_enabled: true,
            ml_weight: 0.5,
            unicode_normalization: true,
            validate_decode: true,
            // Per-chunk decode-through ceiling (conservative vs multi-MiB blobs).
            max_decode_bytes: 512 * 1024,
            max_matches_per_chunk: 1000,
            scan_comments: false,
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
    // PRESET ROUTING NOTE: these core presets are the canonical preset
    // definitions, reachable in the engine only via
    // `ScannerConfig::from(ScanConfig::fast()/thorough()/paranoid())`.
    // The CLI's `build_scanner_config` currently selects the parallel
    // `ScannerConfig::fast()/thorough()` instead, whose values DIVERGE
    // from these (e.g. fast decode-depth 0 vs 2, thorough 10 vs 8). The
    // single-source-of-truth fix is to route the CLI through these core
    // presets and drop the scanner-side duplicates; until that lands,
    // a reader auditing "what --fast does" must check the CLI path, not
    // these methods. Values here are pinned by `crates/core/tests/unit`.

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
            // Deliberately below the default of 20: paranoid mode trades
            // precision for recall and accepts shorter candidates. Not a
            // default disagreement - see `min_secret_len`'s field note on
            // its (currently no-op) live-path status.
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
