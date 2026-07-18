//! Configuration for KeyHog scanning and verification.
//!
//! Provides the [`ScanConfig`] struct used to control decoding depth,
//! entropy thresholds, deduplication strategy, and performance tuning.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::DedupScope;

/// Shipped filesystem per-file scan cap.
///
/// This is the single default used by the core config surface and by
/// `keyhog-sources::FilesystemSource::new`. A caller can still pass
/// `max_file_size = 0` through the source layer to mean "unlimited".
pub const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024;

/// Single owner of the Tier-A generic-entropy gate default (the
/// `ScanConfig::default().entropy_threshold` knob). The scanner's adjudicate
/// fallback (`generic_entropy_floor`) resolves an absent per-scan value to this
/// SAME number, so it references this const rather than re-spelling `4.5`: the
/// two must stay equal by construction, not by two hand-kept literals.
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 4.5;

/// Single owner of the BPE "rare-not-random" gate default (the
/// `ScanConfig::default().entropy_bpe_max_bytes_per_token` knob). An entropy /
/// generic candidate whose `cl100k_base` bytes-per-token is STRICTLY GREATER
/// than this compresses into few common subword tokens, word-like (a probable
/// false positive: dotted API paths, prose, XML) rather than a random secret
/// and is suppressed. `2.2` is the empirical CredData F1 peak (see
/// `keyhog_scanner::entropy::bpe`; the offline A/B lifted F1 0.368→0.424).
///
/// This lives in `keyhog-core` (not next to the gate in `keyhog-scanner`) so
/// `ScanConfig` can default to it WITHOUT a scanner↔core dependency cycle, the
/// gate imports it back. There is exactly ONE definitional home for the value;
/// the scanner re-exports this const under its historical name for the gate's
/// compiled default and its tests, so the two can never drift.
pub const DEFAULT_ENTROPY_BPE_MAX_BYTES_PER_TOKEN: f64 = 2.2;

/// Configuration for a scan run.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    /// Minimum confidence (0.0 to 1.0) required to report a finding.
    pub min_confidence: f64,
    /// Maximum recursive decoding depth (e.g. Base64(Hex(URL(secret)))).
    pub max_decode_depth: usize,
    /// Whether to enable Shannon entropy analysis for unknown high-entropy strings.
    pub entropy_enabled: bool,
    /// Whether to enable entropy analysis even in standard source code files.
    pub entropy_in_source_files: bool,
    /// Global enable for detector-owned entropy ML policy. Each entropy owner
    /// still chooses `disabled`, `lift`, `blend`, or `authoritative` in its TOML;
    /// this switch can only disable those compiled modes for a scan. Opt out
    /// with `--no-entropy-ml-scoring`. No-op when entropy or ML is disabled.
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
    /// BPE "rare-not-random" precision bound: a surviving entropy / generic
    /// candidate whose `cl100k_base` bytes-per-token is STRICTLY GREATER than
    /// this is treated as word-like (a probable false positive, dotted API
    /// paths, prose, XML) and suppressed. Lower = more aggressive suppression
    /// (higher precision, lower recall); higher = looser (a very large value
    /// effectively disables the gate). The compiled default is
    /// [`DEFAULT_ENTROPY_BPE_MAX_BYTES_PER_TOKEN`]. Operators trade precision
    /// for recall per corpus via the `[scan]` TOML key or `--entropy-bpe-max-bytes-per-token`.
    /// A `#[serde(default)]` keeps configs that predate the field on the shipped
    /// bound instead of `f64`'s `0.0`: which would suppress EVERY candidate
    /// (bytes-per-token is always > 0), a silent recall wipeout. No-op unless the
    /// entropy feature is compiled and the gate is reached.
    #[serde(default = "default_entropy_bpe_max_bytes_per_token")]
    pub entropy_bpe_max_bytes_per_token: f64,
    /// Minimum credential length for entropy-based secret detection.
    ///
    /// Named detectors keep their own shape-specific lengths; this floor is
    /// consumed by the scanner's entropy fallback (`--min-secret-len` /
    /// `min_secret_len` in `.keyhog.toml`).
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
pub(crate) const MAX_DECODE_DEPTH_LIMIT: usize = 10;

/// Maximum recursive decode passes accepted from CLI and TOML config.
pub const fn max_decode_depth_limit() -> usize {
    MAX_DECODE_DEPTH_LIMIT
}

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

/// Serde default for [`ScanConfig::entropy_bpe_max_bytes_per_token`]: configs
/// that predate the field get the shipped bound
/// [`DEFAULT_ENTROPY_BPE_MAX_BYTES_PER_TOKEN`] rather than `f64`'s `0.0`: a
/// `0.0` bound would treat every non-empty candidate as word-like and suppress
/// the entire entropy/generic surface (bytes-per-token is always > 0), a silent
/// recall wipeout on old configs. One owner for the value (the core const).
fn default_entropy_bpe_max_bytes_per_token() -> f64 {
    DEFAULT_ENTROPY_BPE_MAX_BYTES_PER_TOKEN
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
    /// `ml_weight` was outside the closed unit interval `[0.0, 1.0]`. The score
    /// blend multiplies by this weight; a value above 1.0 over-weights the model
    /// and a negative one inverts it (both silently distort every confidence).
    #[error("ml_weight must be between 0.0 and 1.0, found {0}")]
    InvalidMlWeight(f64),
    /// `entropy_bpe_max_bytes_per_token` was not a finite value strictly greater
    /// than zero. A `0.0` (or negative / NaN) bound treats EVERY candidate as
    /// word-like and suppresses the entire entropy/generic surface, a silent
    /// recall wipeout (the `#[serde(default)]` guards only configs that OMIT the
    /// key, not an explicit out-of-range value).
    #[error("entropy_bpe_max_bytes_per_token must be a finite value > 0.0, found {0}")]
    InvalidBpeBound(f64),
    /// `entropy_threshold` was not finite. A `NaN` threshold makes every
    /// `entropy >= threshold` comparison false, silently suppressing every
    /// entropy candidate; `±inf` is equally nonsensical as a bits-per-byte floor.
    #[error("entropy_threshold must be a finite number, found {0}")]
    NonFiniteEntropyThreshold(f64),
    /// `entropy_threshold` exceeded the mathematical byte-entropy range.
    #[error("entropy_threshold must be between 0.0 and 8.0 bits per byte, found {0}")]
    InvalidEntropyThreshold(f64),
    /// The TOML text could not be deserialized into a [`ScanConfig`] (syntax
    /// error, wrong type, or an unknown field, the struct is
    /// `#[serde(deny_unknown_fields)]`). The inner string is the `toml` crate's
    /// diagnostic, kept as a `String` so the public error type does not leak the
    /// `toml` version into the API.
    #[error("failed to parse ScanConfig TOML: {0}")]
    Parse(String),
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            // Bench-tuned floor (SecretBench mirror grid-sweep 2026-05-30):
            // 0.40 maximises F1 (0.8642, P=0.984, FP=37) and is the precision
            // sweet spot. 0.30 admits a low-confidence FP band (FP 174); 0.50
            // is WORSE on both axes because the scan-time/ML confidence
            // interaction is non-monotonic in FP.
            // This is the canonical tuned == benched == shipped floor; the
            // post-scan gate (orchestrator/postprocess.rs) and the scan-time
            // generic gate (engine/phase2_generic.rs) both resolve to it.
            min_confidence: 0.40,
            // Aligned with CLI / scanner defaults (`ScannerConfig` derives from this).
            max_decode_depth: 10,
            entropy_enabled: true,
            entropy_in_source_files: false,
            entropy_ml_authoritative: true,
            generic_keyword_low_entropy: true,
            entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
            entropy_bpe_max_bytes_per_token: DEFAULT_ENTROPY_BPE_MAX_BYTES_PER_TOKEN,
            min_secret_len: 16,
            max_file_size: DEFAULT_MAX_FILE_SIZE_BYTES,
            dedup: DedupScope::Credential,
            ml_enabled: true,
            ml_weight: 0.5,
            unicode_normalization: true,
            validate_decode: true,
            // Per-chunk decode-through ceiling (conservative vs multi-MiB blobs).
            max_decode_bytes: 512 * 1024,
            max_matches_per_chunk: 1000,
            scan_comments: false,
            known_prefixes: crate::embedded::CONFIG_KNOWN_PREFIXES
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            secret_keywords: crate::embedded::CONFIG_SECRET_KEYWORDS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            test_keywords: crate::embedded::CONFIG_TEST_KEYWORDS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            placeholder_keywords: crate::embedded::CONFIG_PLACEHOLDER_KEYWORDS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        }
    }
}

impl ScanConfig {
    // PRESET SINGLE SOURCE OF TRUTH (MC-05): the operator-facing presets
    // (`--fast` / `--deep` / `--precision`) live on `ScannerConfig`
    // (`scanner/src/scanner_config.rs::{fast,thorough,high_precision}`), the
    // one path the CLI's `build_scanner_config` actually selects. Earlier this
    // crate also carried `ScanConfig::fast/thorough/paranoid`, but they had ZERO
    // production callers and their values DIVERGED from the shipped ones (e.g.
    // fast decode-depth 2 vs the shipped 0), so a reader auditing "what --fast
    // does" got the wrong answer here. They are deleted rather than re-pointed:
    // until MC-01 collapses `ScannerConfig` back into `ScanConfig`, the presets
    // stay with the config the engine runs, and there is exactly one preset path.

    /// Validate the configuration parameters, failing closed on any value that
    /// would silently break scanning. This is the "separate later step" the
    /// deserialize path deliberately omits (see the `regression_scan_config_fields`
    /// contract): [`ScanConfig::from_toml_str`] composes deserialize + this into
    /// one validated load, and a library consumer who builds a [`ScanConfig`] by
    /// hand calls it directly before handing the config to the engine.
    ///
    /// Every check is NaN-safe: `RangeInclusive::contains` is `false` for `NaN`
    /// (so a `NaN` bound is rejected, not silently admitted), and the entropy
    /// checks reject non-finite values explicitly.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(0.0..=1.0).contains(&self.min_confidence) {
            return Err(ConfigError::InvalidConfidence(self.min_confidence));
        }
        if self.max_decode_depth > MAX_DECODE_DEPTH_LIMIT {
            return Err(ConfigError::DepthTooHigh(self.max_decode_depth));
        }
        if !(0.0..=1.0).contains(&self.ml_weight) {
            return Err(ConfigError::InvalidMlWeight(self.ml_weight));
        }
        // A very large FINITE bound is legal (it "effectively disables the gate"
        // per the field docs); only 0.0, negatives, NaN, and ±inf are rejected.
        if !self.entropy_bpe_max_bytes_per_token.is_finite()
            || self.entropy_bpe_max_bytes_per_token <= 0.0
        {
            return Err(ConfigError::InvalidBpeBound(
                self.entropy_bpe_max_bytes_per_token,
            ));
        }
        // A finite negative threshold is merely permissive (every string clears
        // it); only non-finite values (NaN/±inf) are rejected, because NaN
        // silently suppresses the entire entropy surface.
        if !self.entropy_threshold.is_finite() {
            return Err(ConfigError::NonFiniteEntropyThreshold(
                self.entropy_threshold,
            ));
        }
        if !(0.0..=8.0).contains(&self.entropy_threshold) {
            return Err(ConfigError::InvalidEntropyThreshold(self.entropy_threshold));
        }
        Ok(())
    }

    /// Deserialize a [`ScanConfig`] from a TOML string and validate it, failing
    /// closed on either a parse error or an out-of-range value.
    ///
    /// This is the public, fail-closed loader for the published `keyhog-core`
    /// config surface. `ScanConfig` derives `Deserialize`, so a consumer can
    /// always `toml::from_str` it directly, but that path is UNVALIDATED by
    /// design (validation is a separate step). `from_toml_str` is the ONE place
    /// that composes both, so an external `min_confidence = 5.0` / `ml_weight =
    /// 2.0` / `entropy_bpe_max_bytes_per_token = 0.0` is rejected here exactly as
    /// the CLI rejects it, instead of being silently honored and zeroing recall
    /// downstream. Callers that already hold a `ScanConfig` (e.g. built field by
    /// field) should call [`ScanConfig::validate`] directly.
    pub fn from_toml_str(raw: &str) -> Result<Self, ConfigError> {
        let config: ScanConfig =
            toml::from_str(raw).map_err(|error| ConfigError::Parse(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }
}
