//! Detector-owned entropy floor, fallback confidence, role, shape, and key-material specs.

use serde::{Deserialize, Serialize};

/// One length bucket of a detector's [`DetectorSpec::entropy_floor`]. Owned in the
/// detector's TOML (`entropy_floor = [{ max_len = 24, floor = 3.0 }, { floor = 3.5 }]`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EntropyFloorBucket {
    /// Inclusive maximum candidate length this bucket applies to. Omit on the
    /// final catch-all bucket (applies to any longer candidate).
    #[serde(default)]
    pub max_len: Option<usize>,
    /// Shannon-entropy floor (bits/byte). A candidate scoring below this is
    /// suppressed by the low-entropy gate.
    pub floor: f64,
}

/// Detector-owned identity for a finding emitted by the entropy fallback path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EntropyFallbackMetadata {
    /// Semantic class used by the entropy fallback. This is detector data,
    /// not a scanner-side identity bucket; it keeps the emitted role visible
    /// when several custom detectors share the same generic family.
    pub class: EntropyFallbackClass,
    /// Stable emitted detector id. Must use the `entropy-` namespace.
    pub id: String,
    /// Human-readable finding name.
    pub name: String,
    /// Service family attached to the synthetic finding.
    pub service: String,
}

/// Confidence mapping for one detector's synthetic entropy findings.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntropyFallbackConfidenceSpec {
    /// Maximum base confidence below the detector's high-entropy tier.
    pub low_entropy_max: f64,
    /// Base confidence at or above `entropy_high`.
    pub high_entropy: f64,
    /// Base confidence at or above `entropy_very_high`.
    pub very_high_entropy: f64,
    /// Confidence added when a detector keyword owns the candidate.
    pub keyword_lift: f64,
    /// Maximum confidence this fallback path may emit.
    pub max_confidence: f64,
}

impl EntropyFallbackConfidenceSpec {
    /// Validate probability bounds and monotonic evidence tiers.
    pub fn validate(self) -> Result<(), &'static str> {
        let values = [
            self.low_entropy_max,
            self.high_entropy,
            self.very_high_entropy,
            self.keyword_lift,
            self.max_confidence,
        ];
        if values
            .into_iter()
            .any(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        {
            return Err("all values must be finite probabilities in [0.0, 1.0]");
        }
        if self.low_entropy_max > self.high_entropy
            || self.high_entropy > self.very_high_entropy
            || self.very_high_entropy > self.max_confidence
        {
            return Err(
                "confidence tiers must satisfy low_entropy_max <= high_entropy <= very_high_entropy <= max_confidence",
            );
        }
        Ok(())
    }
}

/// Confidence mapping for a detector-owned generic assignment candidate.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericAssignmentConfidenceSpec {
    /// Base confidence for ordinary source and configuration content.
    pub ordinary_base: f64,
    /// Base confidence for test content when test-path penalties are enabled.
    pub test_base: f64,
    /// Base confidence for documentation when test-path penalties are enabled.
    pub documentation_base: f64,
    /// Base confidence for comments under the default comment policy.
    pub comment_base: f64,
    /// Base confidence for comments when the operator enables comment scanning.
    pub scanned_comment_base: f64,
    /// Shannon entropy at which the entropy lift starts.
    pub entropy_reference: f64,
    /// Confidence gained per entropy bit above `entropy_reference`.
    pub entropy_gain_per_bit: f64,
    /// Maximum confidence contributed by entropy.
    pub entropy_lift_max: f64,
    /// Byte length at which the length lift starts.
    pub length_reference: usize,
    /// Confidence gained per byte above `length_reference`.
    pub length_gain_per_byte: f64,
    /// Maximum confidence contributed by length.
    pub length_lift_max: f64,
    /// Maximum confidence this generic assignment path may emit.
    pub max_confidence: f64,
}

impl GenericAssignmentConfidenceSpec {
    /// Validate probability bounds and the byte-entropy reference domain.
    pub fn validate(self) -> Result<(), &'static str> {
        let probabilities = [
            self.ordinary_base,
            self.test_base,
            self.documentation_base,
            self.comment_base,
            self.scanned_comment_base,
            self.entropy_gain_per_bit,
            self.entropy_lift_max,
            self.length_gain_per_byte,
            self.length_lift_max,
            self.max_confidence,
        ];
        if probabilities
            .into_iter()
            .any(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        {
            return Err(
                "bases, gains, lift caps, and max_confidence must be finite values in [0.0, 1.0]",
            );
        }
        if !self.entropy_reference.is_finite()
            || !(0.0..=u8::BITS as f64).contains(&self.entropy_reference)
        {
            return Err("entropy_reference must be finite and in [0.0, 8.0]");
        }
        if [
            self.ordinary_base,
            self.test_base,
            self.documentation_base,
            self.comment_base,
            self.scanned_comment_base,
        ]
        .into_iter()
        .any(|base| base > self.max_confidence)
        {
            return Err("every context base must be less than or equal to max_confidence");
        }
        Ok(())
    }
}

impl EntropyFallbackMetadata {
    /// Whether this metadata can safely identify a synthetic entropy finding.
    /// IDs stay lowercase and delimiter-stable so reports, hashes, and
    /// suppression receipts cannot acquire ambiguous namespace variants.
    pub fn has_valid_identity(&self) -> bool {
        let Some(suffix) = self.id.strip_prefix("entropy-") else {
            return false;
        };
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !self.name.trim().is_empty()
            && !self.service.trim().is_empty()
    }
}

/// Semantic role of a detector-owned synthetic entropy finding.
///
/// The role is deliberately separate from the emitted id and display text:
/// operators may rename a detector's finding without changing which evidence
/// family owns the candidate. Runtime emission resolves the active detector's
/// complete metadata, so this enum never acts as a scanner-wide identity
/// fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EntropyFallbackClass {
    /// Anchor-free high-entropy material owned by the generic-secret policy.
    #[default]
    Generic,
    /// Password-family assignment or isolated password evidence.
    Password,
    /// Token/secret keyword-family evidence.
    Token,
    /// API/access-key and cryptographic-key evidence.
    ApiKey,
}

/// Detector-owned entry roles for the shared entropy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntropyDetectionRole {
    /// Own anchor-free high-entropy candidates.
    KeywordFree,
    /// Own isolated bare candidates admitted by a detector shape policy.
    IsolatedBare,
    /// Own credential keywords not explicitly claimed by another detector.
    UnclaimedKeyword,
}

impl EntropyDetectionRole {
    /// Stable serialized spelling used by diagnostics and policy hashes.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeywordFree => "keyword-free",
            Self::IsolatedBare => "isolated-bare",
            Self::UnclaimedKeyword => "unclaimed-keyword",
        }
    }
}

impl EntropyFallbackClass {
    /// Stable serialized spelling used by explain output and policy hashes.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Password => "password",
            Self::Token => "token",
            Self::ApiKey => "api-key",
        }
    }
}

/// Character class an isolated entropy shape admits. Replaces the former
/// per-shape enum variant so a new shape family is TOML data, not scanner code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShapeCharset {
    /// Lowercase letters and digits only.
    LowerAlnum,
    /// Hexadecimal digits only.
    Hex,
    /// Standard base64 alphabet (`A-Za-z0-9`, `+`, `/`, optional `=` padding).
    Base64Standard,
    /// URL-safe base64 alphabet (`A-Za-z0-9`, `-`, `_`).
    Base64Url,
}

fn default_shape_separator() -> char {
    '-'
}

/// Fixed-width separator grouping, e.g. a Bluesky app password's four
/// dash-separated groups of four. Absent means an ungrouped run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShapeGrouping {
    /// Number of separator-delimited groups.
    pub group_count: usize,
    /// Exact byte length of every group.
    pub group_length: usize,
    /// Character that separates the groups.
    #[serde(default = "default_shape_separator")]
    pub separator: char,
}

/// A declarative structural shape that may cross a detector's broad isolated
/// entropy floor. Every field is detector TOML data and the scanner keeps one
/// general matcher, so a new shape family (base64, hex block) is added by a
/// detector TOML rather than a scanner enum variant.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntropyShapeSpec {
    /// Character class the candidate body must consist of.
    pub charset: ShapeCharset,
    /// Minimum Shannon entropy in bits/byte.
    pub entropy_floor: f64,
    /// Minimum candidate length used by the isolated-shape revisit. This may be
    /// below the detector's broad keyword-free minimum.
    pub special_min_length: usize,
    /// Optional separator grouping. Absent means an ungrouped run.
    #[serde(default)]
    pub grouping: Option<ShapeGrouping>,
    /// Require both a lowercase and an uppercase letter.
    #[serde(default)]
    pub require_mixed_case: bool,
    /// Require at least one digit.
    #[serde(default)]
    pub require_digit: bool,
    /// Minimum count of symbol (non-alphanumeric) bytes.
    #[serde(default)]
    pub min_symbols: usize,
    /// Require at least one non-hex alphabetic byte, distinguishing an app
    /// password from a pure-hex digest of the same layout.
    #[serde(default)]
    pub require_non_hex_alpha: bool,
    /// When grouped, require every group to contain at least one letter and one
    /// digit (the app-password per-group rule).
    #[serde(default)]
    pub require_group_alpha_digit: bool,
}

/// One detector-local pure-hex key-material policy.
///
/// A candidate is eligible only when its captured assignment key matches one of
/// `keywords`, ends with one of `suffixes`, and is not in `excluded_keywords`
/// after normal assignment-key case/separator normalization. Its exact
/// character count must appear in `lengths`. The scanner still applies entropy,
/// placeholder, context, and reporting gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CanonicalHexKeyMaterialSpec {
    /// Exact pure-hex character counts admitted by this policy.
    #[serde(default)]
    pub lengths: Vec<usize>,
    /// Assignment keys owned by a phase-2 generic policy. Each must also appear
    /// in the detector's top-level `keywords` list. Regex policies leave this
    /// empty because their matched pattern supplies the scope.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Normalized phase-2 assignment-key suffixes that may own this policy. This
    /// expresses vendor-prefixed names such as `stripe_secret_key` without a
    /// scanner-global suffix heuristic.
    #[serde(default)]
    pub suffixes: Vec<String>,
    /// Normalized phase-2 assignment keys excluded from suffix ownership, such
    /// as the ambiguous `license_key` shape.
    #[serde(default)]
    pub excluded_keywords: Vec<String>,
}

