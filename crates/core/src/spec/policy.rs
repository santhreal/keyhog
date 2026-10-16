//! Detector-owned decode-transform, ML, confidence, validator, and plausibility policies.

use serde::{Deserialize, Serialize};

/// Literal admission prefixes for detector-owned evasion recovery.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorDecodeTransformSpec {
    /// Plaintext prefixes whose character-reversed spelling may admit reverse
    /// recovery. Prefixes shorter than three bytes are rejected because they
    /// create excessive accidental matches in encoded data.
    #[serde(default)]
    pub reverse_prefixes: Vec<String>,
    /// Plaintext prefixes whose rotated spellings may admit Caesar/ROT-N
    /// recovery. A prefix must contain at least one ASCII letter so rotation
    /// can change it.
    #[serde(default)]
    pub caesar_prefixes: Vec<String>,
}

impl DetectorDecodeTransformSpec {
    /// Validate transform prefix shape and per-list uniqueness.
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();
        validate_decode_transform_prefixes(
            "reverse_prefixes",
            &self.reverse_prefixes,
            true,
            &mut issues,
        );
        validate_decode_transform_prefixes(
            "caesar_prefixes",
            &self.caesar_prefixes,
            false,
            &mut issues,
        );
        issues
    }
}

fn validate_decode_transform_prefixes(
    field: &str,
    prefixes: &[String],
    reverse: bool,
    issues: &mut Vec<String>,
) {
    let mut seen = std::collections::HashSet::with_capacity(prefixes.len());
    for prefix in prefixes {
        if prefix.is_empty() || !prefix.is_ascii() {
            issues.push(format!("{field} entry {prefix:?} must be non-empty ASCII"));
            continue;
        }
        if reverse && prefix.len() < 3 {
            issues.push(format!(
                "{field} entry {prefix:?} must contain at least three bytes"
            ));
        }
        if !reverse && !prefix.bytes().any(|byte| byte.is_ascii_alphabetic()) {
            issues.push(format!(
                "{field} entry {prefix:?} must contain an ASCII letter"
            ));
        }
        if !seen.insert(prefix.as_str()) {
            issues.push(format!("{field} contains duplicate prefix {prefix:?}"));
        }
    }
}

/// How the shared ML model participates in one detector path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectorMlMode {
    /// Do not run model inference for this path.
    #[default]
    Disabled,
    /// Let the model raise structurally derived confidence but never veto a
    /// detector match. The detector-owned weight controls the fraction of the
    /// positive model delta that is applied.
    Lift,
    /// Combine model confidence with the detector's structural evidence.
    Blend,
    /// Let the model score replace the heuristic score for weakly anchored
    /// candidates where entropy magnitude is not positive evidence.
    Authoritative,
}

impl DetectorMlMode {
    /// Stable TOML spelling used by diagnostics and semantic hashes.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Lift => "lift",
            Self::Blend => "blend",
            Self::Authoritative => "authoritative",
        }
    }
}

/// Complete detector-local configuration for the shared ML scoring engine.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorMlPolicySpec {
    /// Policy for regex and generic-assignment matches owned by this detector.
    pub match_mode: DetectorMlMode,
    /// Policy for entropy-fallback candidates owned by this detector.
    pub entropy_mode: DetectorMlMode,
    /// Model contribution for `lift` and `blend`, in the closed interval `[0, 1]`.
    pub weight: f64,
    /// Number of source lines on each side of the candidate supplied to feature
    /// extraction. Zero intentionally restricts inference to the candidate line.
    pub context_radius_lines: usize,
}

/// Complete detector-local confidence policy for regex candidates.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorMatchConfidenceSpec {
    /// Weight earned by a detector-specific literal prefix.
    pub literal_prefix_weight: f64,
    /// Weight earned by a required contextual capture.
    pub context_anchor_weight: f64,
    /// Full weight earned at the very-high entropy tier.
    pub entropy_weight: f64,
    /// Partial weight earned at the resolved high entropy tier.
    pub high_entropy_partial_weight: f64,
    /// Shannon threshold for moderate entropy evidence.
    pub moderate_entropy_threshold: f64,
    /// Weight earned at the moderate entropy tier.
    pub moderate_entropy_weight: f64,
    /// Shannon floor below which a long match receives a penalty.
    pub low_entropy_penalty_floor: f64,
    /// Minimum byte length above which the low-entropy penalty applies.
    pub low_entropy_min_match_length: usize,
    /// Multiplier applied when the low-entropy penalty fires.
    pub low_entropy_penalty_multiplier: f64,
    /// Weight earned when detector-owned context is nearby.
    pub keyword_nearby_weight: f64,
    /// Weight earned in a sensitive file.
    pub sensitive_file_weight: f64,
    /// Weight earned when a companion capture is present.
    pub companion_weight: f64,
    /// Margin above the resolved high tier for full entropy evidence.
    pub very_high_entropy_margin: f64,
    /// Structural floor for a non-generic match carrying a compiled anchor.
    pub named_anchor_floor: Option<f64>,
    /// Final score for an unaccompanied generic match rejected by the cheap
    /// promise gate before model inference.
    pub low_promise_confidence: Option<f64>,
    /// Confidence multiplier for an assignment context.
    pub assignment_context_multiplier: f64,
    /// Confidence multiplier for a string-literal context.
    pub string_literal_context_multiplier: f64,
    /// Confidence multiplier when source context is unknown.
    pub unknown_context_multiplier: f64,
    /// Confidence multiplier for documentation context.
    pub documentation_context_multiplier: f64,
    /// Confidence multiplier for comment context.
    pub comment_context_multiplier: f64,
    /// Confidence multiplier for test-code context.
    pub test_context_multiplier: f64,
    /// Confidence multiplier for encrypted or sealed context.
    pub encrypted_context_multiplier: f64,
    /// Hard-suppression threshold for comment, test, and documentation context.
    pub soft_context_suppression_threshold: f64,
    /// Hard-suppression threshold for encrypted or sealed context.
    pub encrypted_context_suppression_threshold: f64,
    /// Detector-owned policy applied after optional model scoring.
    pub post_match: DetectorPostMatchConfidenceSpec,
}

/// Detector-local confidence penalties applied after optional model scoring.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorPostMatchConfidenceSpec {
    /// Multiplier for a surface or decoded placeholder word.
    pub placeholder_multiplier: f64,
    /// Minimum unique-byte ratio before the value receives a diversity penalty.
    pub minimum_byte_diversity: f64,
    /// Multiplier for values below `minimum_byte_diversity`.
    pub low_diversity_multiplier: f64,
    /// Maximum repeated-byte run ratio before the value receives a penalty.
    pub maximum_repeat_ratio: f64,
    /// Absolute repeated-byte run length that receives a penalty regardless of ratio.
    pub degenerate_run_min_length: usize,
    /// Multiplier for values exceeding either repeated-byte limit.
    pub degenerate_repeat_multiplier: f64,
    /// Multiplier for decoded data envelopes. Omit it when the detector's
    /// anchored credential shape makes this evidence inapplicable.
    pub data_envelope_multiplier: Option<f64>,
    /// Multiplier for findings under fixture or example path components.
    pub fixture_path_multiplier: f64,
    /// Reapply the source-context multiplier to model scores below this floor.
    pub ml_context_reapply_below: f64,
}

impl DetectorPostMatchConfidenceSpec {
    /// Validate ratios, multipliers, and the repeated-run boundary.
    pub fn validate(self) -> Result<(), &'static str> {
        if [
            self.placeholder_multiplier,
            self.minimum_byte_diversity,
            self.low_diversity_multiplier,
            self.maximum_repeat_ratio,
            self.degenerate_repeat_multiplier,
            self.fixture_path_multiplier,
            self.ml_context_reapply_below,
        ]
        .into_iter()
        .chain(self.data_envelope_multiplier)
        .any(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        {
            return Err("post-match ratios and multipliers must be finite values in [0.0, 1.0]");
        }
        if self.degenerate_run_min_length == 0 {
            return Err("post-match degenerate_run_min_length must be greater than zero");
        }
        Ok(())
    }
}

impl DetectorMatchConfidenceSpec {
    /// Validate probabilities, entropy domains, and evidence ordering.
    pub fn validate(self) -> Result<(), &'static str> {
        self.post_match.validate()?;
        let probabilities = [
            self.literal_prefix_weight,
            self.context_anchor_weight,
            self.entropy_weight,
            self.high_entropy_partial_weight,
            self.moderate_entropy_weight,
            self.low_entropy_penalty_multiplier,
            self.keyword_nearby_weight,
            self.sensitive_file_weight,
            self.companion_weight,
            self.assignment_context_multiplier,
            self.string_literal_context_multiplier,
            self.unknown_context_multiplier,
            self.documentation_context_multiplier,
            self.comment_context_multiplier,
            self.test_context_multiplier,
            self.encrypted_context_multiplier,
            self.soft_context_suppression_threshold,
            self.encrypted_context_suppression_threshold,
        ];
        if probabilities
            .into_iter()
            .chain(self.named_anchor_floor)
            .chain(self.low_promise_confidence)
            .any(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        {
            return Err("weights, multipliers, floors, and final scores must be finite values in [0.0, 1.0]");
        }
        if [
            self.moderate_entropy_threshold,
            self.low_entropy_penalty_floor,
            self.very_high_entropy_margin,
        ]
        .into_iter()
        .any(|value| !value.is_finite() || !(0.0..=u8::BITS as f64).contains(&value))
        {
            return Err("entropy thresholds and margins must be finite values in [0.0, 8.0]");
        }
        if self.low_entropy_penalty_floor > self.moderate_entropy_threshold {
            return Err("low_entropy_penalty_floor must not exceed moderate_entropy_threshold");
        }
        if self.moderate_entropy_weight > self.high_entropy_partial_weight
            || self.high_entropy_partial_weight > self.entropy_weight
        {
            return Err("entropy weights must satisfy moderate <= high partial <= full");
        }
        if self.literal_prefix_weight
            + self.context_anchor_weight
            + self.entropy_weight
            + self.keyword_nearby_weight
            + self.sensitive_file_weight
            + self.companion_weight
            <= 0.0
        {
            return Err("at least one maximum signal weight must be positive");
        }
        Ok(())
    }
}

/// Exact base64 dialect accepted by a detector-owned offline validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectorBase64Alphabet {
    /// Canonical RFC 4648 base64 with `+`/`/` and `=` padding.
    Standard,
    /// RFC 4648 base64 with `+`/`/` and no `=` padding.
    StandardNoPad,
    /// URL-safe base64 with `-`/`_` and `=` padding.
    UrlSafe,
    /// URL-safe base64 with `-`/`_` and no `=` padding.
    UrlSafeNoPad,
}

/// An offline validator declared by one detector.
///
/// The enum is deliberately closed and typed: malformed combinations are
/// rejected while loading detector TOML instead of becoming runtime defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DetectorValidatorSpec {
    /// CRC32 over a fixed entropy body, encoded as a fixed-width base62 suffix.
    Crc32Base62 {
        /// Literal token prefixes this validator claims.
        #[serde(default)]
        prefixes: Vec<String>,
        /// Exact length of the entropy body between the prefix and the checksum.
        entropy_len: usize,
        /// Exact length of the base62-encoded CRC32 suffix.
        checksum_len: usize,
        /// Reject a candidate that carries extra token bytes past the declared length.
        reject_overlong: bool,
        /// Confidence assigned when the checksum verifies.
        confidence_floor: f64,
    },
    /// GitHub fine-grained PAT CRC32 layout with two underscore-separated
    /// segments and compatibility for the two formats GitHub has emitted.
    GithubFineGrainedCrc32 {
        /// Literal token prefixes this validator claims.
        #[serde(default)]
        prefixes: Vec<String>,
        /// Exact length of the segment before the underscore separator.
        left_len: usize,
        /// Exact length of the segment after the underscore separator.
        right_len: usize,
        /// Exact length of the base62-encoded CRC32 suffix.
        checksum_len: usize,
        /// Confidence assigned when the checksum verifies.
        confidence_floor: f64,
    },
    /// A base64 payload whose successful decode is offline authenticity
    /// evidence, such as the macaroon carried by a PyPI API token.
    Base64Payload {
        /// Literal token prefixes this validator claims.
        #[serde(default)]
        prefixes: Vec<String>,
        /// Base64 dialect the payload must decode under.
        alphabet: DetectorBase64Alphabet,
        /// Smallest accepted encoded payload length.
        min_encoded_len: usize,
        /// Largest accepted encoded payload length.
        max_encoded_len: usize,
        /// Smallest accepted decoded payload length.
        min_decoded_len: usize,
        /// Confidence assigned when the payload decodes.
        confidence_floor: f64,
    },
    /// The detector's own patterns are the complete structural contract. The
    /// scanner compiles anchored copies once for generic/public validation;
    /// named matches reuse the already-proven pattern result without rerunning
    /// a second regex.
    PatternShape {
        /// Literal token prefixes this validator claims.
        #[serde(default)]
        prefixes: Vec<String>,
        /// Whether a candidate that begins with a complete declared pattern but
        /// continues with provider-token bytes is an unknown future shape
        /// (`true`) or malformed (`false`).
        allow_overlong: bool,
    },
    /// JSON Web Token (JWT) structural validation (RFC 7519).
    /// Validates 3 dot-separated base64url segments, parseable header JSON,
    /// and valid signature algorithm.
    Jwt {
        /// Literal token prefixes this validator claims.
        #[serde(default)]
        prefixes: Vec<String>,
        /// Reject unsigned `alg = "none"` tokens.
        #[serde(default)]
        reject_alg_none: bool,
        /// Confidence assigned when the JWT structure is valid.
        confidence_floor: f64,
    },
    /// Canonical 8-4-4-4-12 hyphenated hexadecimal UUID validation (RFC 4122 / RFC 9562).
    Uuid {
        /// Literal token prefixes this validator claims.
        #[serde(default)]
        prefixes: Vec<String>,
        /// Confidence assigned when the UUID is structurally valid.
        confidence_floor: f64,
    },
    /// Fixed-length hexadecimal digest / hash validation.
    HexHash {
        /// Literal token prefixes this validator claims.
        #[serde(default)]
        prefixes: Vec<String>,
        /// Expected hexadecimal payload length.
        expected_len: usize,
        /// Whether uppercase hex characters are rejected (lowercase only).
        #[serde(default)]
        lowercase_only: bool,
        /// Confidence assigned when the hex hash is structurally valid.
        confidence_floor: f64,
    },
    /// Luhn (mod 10) checksum validation algorithm (ISO/IEC 7812).
    LuhnChecksum {
        /// Literal token prefixes this validator claims.
        #[serde(default)]
        prefixes: Vec<String>,
        /// Minimum accepted digit length.
        min_len: usize,
        /// Maximum accepted digit length.
        max_len: usize,
        /// Confidence assigned when the Luhn checksum verifies.
        confidence_floor: f64,
    },
}

impl DetectorValidatorSpec {
    /// Literal prefixes claimed by this validator.
    pub fn prefixes(&self) -> &[String] {
        match self {
            Self::Crc32Base62 { prefixes, .. }
            | Self::GithubFineGrainedCrc32 { prefixes, .. }
            | Self::Base64Payload { prefixes, .. }
            | Self::PatternShape { prefixes, .. }
            | Self::Jwt { prefixes, .. }
            | Self::Uuid { prefixes, .. }
            | Self::HexHash { prefixes, .. }
            | Self::LuhnChecksum { prefixes, .. } => prefixes,
        }
    }

    /// Confidence floor earned by positive offline proof, when applicable.
    pub fn confidence_floor(&self) -> Option<f64> {
        match self {
            Self::Crc32Base62 {
                confidence_floor, ..
            }
            | Self::GithubFineGrainedCrc32 {
                confidence_floor, ..
            }
            | Self::Base64Payload {
                confidence_floor, ..
            }
            | Self::Jwt {
                confidence_floor, ..
            }
            | Self::Uuid {
                confidence_floor, ..
            }
            | Self::HexHash {
                confidence_floor, ..
            }
            | Self::LuhnChecksum {
                confidence_floor, ..
            } => Some(*confidence_floor),
            Self::PatternShape { .. } => None,
        }
    }
}

/// Strict candidate-plausibility policy owned by one detector TOML.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorPlausibilityPolicySpec {
    /// Entropy floor for mixed alphabetic/numeric values.
    pub mixed_alnum_floor: f64,
    /// Entropy floor for symbolic values carrying a credential anchor.
    pub symbolic_entropy_floor: f64,
    /// Minimum entropy in the second half of a long value.
    pub second_half_entropy_floor: f64,
    /// Minimum byte length at which second-half entropy is required.
    pub second_half_min_len: usize,
    /// Minimum byte length at which distinct-character diversity is required.
    pub unique_chars_min_len: usize,
    /// Minimum distinct characters required at and above `unique_chars_min_len`.
    pub min_unique_chars: usize,
    /// Longest unanchored all-hex value that is not rejected as key material.
    pub unanchored_hex_max_len: usize,
    /// Longest single-character repetition that is not rejected.
    pub identical_char_max_len: usize,
    /// Minimum byte length for an isolated structured dotted token.
    pub structured_dotted_min_len: usize,
    /// Minimum byte length for the mixed alphabetic/numeric carve-out.
    pub mixed_alnum_min_len: usize,
    /// Shannon floor for isolated mixed-case alphanumeric tokens, with or
    /// without an underscore separator.
    pub isolated_mixed_entropy_floor: f64,
    /// Minimum byte length for isolated symbolic opaque-token shapes.
    pub isolated_symbolic_min_len: usize,
    /// Minimum number of symbol bytes in an isolated symbolic shape.
    pub isolated_symbolic_min_symbols: usize,
    /// Require at least one symbolic byte other than underscore.
    pub isolated_symbolic_requires_non_underscore: bool,
    /// Minimum number of symbol bytes in an isolated alpha-only symbolic shape.
    pub isolated_alpha_only_min_symbols: usize,
    /// Minimum fraction of bytes that must be alphabetic in an isolated
    /// alpha-only symbolic shape.
    pub isolated_alpha_only_min_alpha_ratio: f64,
    /// Minimum fraction of characters that must be alphanumeric.
    pub min_alnum_ratio: f64,
    /// Maximum byte length for a source type-name shape.
    pub source_type_name_max_len: usize,
    /// Minimum uppercase byte count for a source type-name shape.
    pub source_type_name_min_uppercase: usize,
    /// Minimum byte length at which a high-entropy punctuation payload may
    /// bypass URL and path-shape suppression.
    pub url_path_high_entropy_min_len: usize,
    /// Minimum byte length for the left component of `opaque:opaque` tokens.
    pub isolated_colon_left_min_len: usize,
    /// Minimum byte length for the right component of `opaque:opaque` tokens.
    pub isolated_colon_right_min_len: usize,
    /// Shannon floor for an unanchored leading-slash base64 token.
    pub leading_slash_base64_entropy_floor: f64,
    /// Minimum byte length for an unanchored leading-slash base64 token.
    pub leading_slash_base64_min_len: usize,
    /// Margin added to the Tier-A entropy threshold before comparing an
    /// unanchored keyword-free candidate. Required only for the detector that
    /// claims the `keyword-free` entropy role.
    #[serde(default)]
    pub keyword_free_operator_margin: Option<f64>,
    /// Reject periodic values, including a truncated final repetition.
    pub reject_repeated_blocks: bool,
    /// Admit an anchored alphabetic value after the other shape gates pass.
    pub allow_alphabetic_credential: bool,
    /// Reject source-language identifier shapes.
    pub reject_program_identifiers: bool,
    /// Reject mixed alphanumeric source-symbol shapes that include digits.
    pub reject_source_symbol_identifiers: bool,
    /// Reject dash-segmented product serial and identifier shapes.
    pub reject_dash_segmented_alnum: bool,
}

impl Default for DetectorMlPolicySpec {
    fn default() -> Self {
        Self {
            match_mode: DetectorMlMode::Disabled,
            entropy_mode: DetectorMlMode::Disabled,
            weight: 0.0,
            context_radius_lines: 0,
        }
    }
}

