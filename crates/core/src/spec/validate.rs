//! Detector quality gate validation rules used while loading TOML specs.

use super::{
    CanonicalHexKeyMaterialSpec, DetectorKind, DetectorRelationKind, DetectorSpec,
    EvidenceRequirement, EvidenceScope, HARD_NEGATIVE_TEST_EVIDENCE_SCHEMA_VERSION,
};
use serde::Serialize;
use std::collections::{hash_map::Entry, HashMap, HashSet};

const MAX_REGEX_PATTERN_LEN: usize = 4096;
const MAX_COMPANION_WITHIN_LINES: usize = 100;
const MAX_COMPANION_WITHIN_BYTES: usize = 1_048_576;
const MIN_HTTP_STATUS: u16 = 100;
const MAX_HTTP_STATUS: u16 = 599;
// MAX_REGEX_AST_NODES / MAX_REGEX_ALTERNATION_BRANCHES /
// MAX_REGEX_REPEAT_BOUND were originally defined here too but are the
// canonical constants in `validate/regex_complexity.rs` (which is where
// they're actually consumed). Duplicates here had no consumers - clippy
// `dead_code` flagged them. Re-imports happen via the `use
// regex_complexity::validate_regex_complexity;` below.

/// Quality issue found in a detector spec.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::QualityIssue;
///
/// let issue = QualityIssue::Warning("add keywords".into());
/// assert!(matches!(issue, QualityIssue::Warning(_)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum QualityIssue {
    /// A gate violation that makes the detector unloadable.
    Error(String),
    /// A gate violation that is reported but does not block loading.
    Warning(String),
}

/// Validate schema-independent detector quality rules.
///
/// Corpus-version gates are applied by the detector loader. Call
/// [`validate_detector_for_corpus_schema`] when validating an authored corpus
/// outside that loader.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::{detector_spec_by_id, validate_detector};
///
/// let detector = detector_spec_by_id("aws-access-key")
///     .expect("the embedded detector corpus contains AWS access keys");
///
/// let issues = validate_detector(&detector);
/// assert!(issues.is_empty(), "{issues:?}");
/// ```
pub fn validate_detector(spec: &DetectorSpec) -> Vec<QualityIssue> {
    validate_detector_with_hard_negative_evidence(spec, false)
}

/// Validate detector quality rules owned by a specific corpus schema.
pub fn validate_detector_for_corpus_schema(
    spec: &DetectorSpec,
    corpus_schema_version: u32,
) -> Vec<QualityIssue> {
    validate_detector_with_hard_negative_evidence(
        spec,
        corpus_schema_version >= HARD_NEGATIVE_TEST_EVIDENCE_SCHEMA_VERSION,
    )
}

fn validate_detector_with_hard_negative_evidence(
    spec: &DetectorSpec,
    enforce_complete_hard_negative_evidence: bool,
) -> Vec<QualityIssue> {
    let mut issues = Vec::new();
    let mut regex_cache = RegexAstCache::default();
    validate_identity(spec, &mut issues);
    validate_patterns_present(spec, &mut issues);
    validate_regexes(spec, &mut issues, &mut regex_cache);
    validate_required_literals(spec, &mut issues);
    validate_pattern_groups(spec, &mut issues, &mut regex_cache);
    validate_keywords(spec, &mut issues);
    validate_simdsieve_prefixes(spec, &mut issues);
    validate_offline_validators(spec, &mut issues);
    validate_decode_transforms(spec, &mut issues);
    validate_pattern_specificity(spec, &mut issues, &mut regex_cache);
    validate_companions(spec, &mut issues, &mut regex_cache);
    validate_detector_relations(spec, &mut issues);
    validate_verify_spec(spec, &mut issues);
    validate_thresholds(spec, &mut issues);
    validate_entropy_floor(spec, &mut issues);
    validate_decoded_hex_key_material_lengths(spec, &mut issues);
    validate_canonical_hex_key_material(spec, &mut issues);
    validate_credential_shape(spec, &mut issues);
    validate_generic_assignment_suffixes(spec, &mut issues);
    validate_detector_allowlists(spec, &mut issues);
    validate_semantic_policy(spec, &mut issues);
    validate_detector_test_evidence(spec, &mut issues, enforce_complete_hard_negative_evidence);
    issues
}

fn validate_detector_test_evidence(
    spec: &DetectorSpec,
    issues: &mut Vec<QualityIssue>,
    enforce_complete_hard_negative_evidence: bool,
) {
    for (test_index, test) in spec.tests.iter().enumerate() {
        if let Some(pattern_index) = test.pattern_index {
            if usize::try_from(pattern_index)
                .ok()
                .is_none_or(|index| index >= spec.patterns.len())
            {
                issues.push(QualityIssue::Error(format!(
                    "tests[{test_index}].pattern_index {pattern_index} is out of range for {} patterns",
                    spec.patterns.len()
                )));
            }
        }
        let has_positive = test
            .test_positive
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let has_negative = test
            .test_negative
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        if test.pattern_index.is_some() && !has_positive && !has_negative {
            issues.push(QualityIssue::Error(format!(
                "tests[{test_index}].pattern_index requires non-empty positive or negative evidence"
            )));
        }
        if test.negative_class.is_some() && test.pattern_index.is_none() {
            issues.push(QualityIssue::Error(format!(
                "tests[{test_index}].negative_class requires pattern_index"
            )));
        }
        if test.negative_class.is_some() && !has_negative {
            issues.push(QualityIssue::Error(format!(
                "tests[{test_index}].negative_class requires non-empty test_negative"
            )));
        }
    }

    if !enforce_complete_hard_negative_evidence {
        return;
    }

    if !spec.semantic_policy().is_enforcement_capable() {
        return;
    }

    for pattern_index in 0..spec.patterns.len() {
        let Ok(pattern_index_u32) = u32::try_from(pattern_index) else {
            issues.push(QualityIssue::Error(
                "detector pattern count exceeds the representable pattern_index range".into(),
            ));
            break;
        };
        let has_positive = spec.tests.iter().any(|test| {
            test.pattern_index == Some(pattern_index_u32)
                && test
                    .test_positive
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
        });
        if !has_positive {
            issues.push(QualityIssue::Error(format!(
                "enforcement-capable pattern {pattern_index} requires direct positive evidence"
            )));
        }

        let has_negative = spec.tests.iter().any(|test| {
            test.pattern_index == Some(pattern_index_u32)
                && test.negative_class.is_some()
                && test
                    .test_negative
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
        });
        if !has_negative {
            issues.push(QualityIssue::Error(format!(
                "enforcement-capable pattern {pattern_index} requires a named direct hard negative"
            )));
        }
    }
}

fn validate_semantic_policy(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    let mut source_roles = HashSet::new();
    for role in &spec.allowed_source_roles {
        if !source_roles.insert(*role) {
            issues.push(QualityIssue::Error(format!(
                "allowed_source_roles contains duplicate role `{}`",
                role.as_str()
            )));
        }
    }
    if spec
        .allowed_source_roles
        .contains(&crate::SemanticSourceRole::Unknown)
    {
        issues.push(QualityIssue::Error(
            "allowed_source_roles cannot contain `unknown`; omit the field to preserve compatibility behavior".into(),
        ));
    }

    let mut evidence = HashSet::new();
    for requirement in &spec.required_evidence {
        if !evidence.insert(*requirement) {
            issues.push(QualityIssue::Error(format!(
                "required_evidence contains duplicate requirement `{}`",
                requirement.as_str()
            )));
        }
    }
}
fn validate_generic_assignment_suffixes(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    for (field, suffixes) in [
        ("generic_vendor_suffixes", &spec.generic_vendor_suffixes),
        (
            "generic_assignment_tail_suffixes",
            &spec.generic_assignment_tail_suffixes,
        ),
    ] {
        if !suffixes.is_empty() && spec.kind != crate::DetectorKind::Phase2Generic {
            issues.push(QualityIssue::Error(format!(
                "{field} is only valid for a phase2-generic detector"
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        for suffix in suffixes {
            if suffix.is_empty()
                || suffix != &suffix.to_ascii_lowercase()
                || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
            {
                issues.push(QualityIssue::Error(format!(
                    "{field} entry {suffix:?} must be non-empty lowercase ASCII alphanumeric"
                )));
            } else if !seen.insert(suffix.as_str()) {
                issues.push(QualityIssue::Error(format!(
                    "{field} contains duplicate suffix {suffix:?}"
                )));
            }
        }
    }
}

fn validate_decode_transforms(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    for issue in spec.decode_transforms.validate() {
        issues.push(QualityIssue::Error(format!("decode_transforms.{issue}")));
    }
}

fn validate_required_literals(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    for (index, pattern) in spec.patterns.iter().enumerate() {
        if let Err(reason) = pattern.validate_required_literals() {
            issues.push(QualityIssue::Error(format!(
                "patterns[{index}].required_literals: {reason}"
            )));
        }
    }
}

fn validate_offline_validators(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    let mut claimed_prefixes = std::collections::HashSet::new();
    for (index, validator) in spec.validators.iter().enumerate() {
        let prefixes = validator.prefixes();
        if prefixes.is_empty() {
            match validator {
                crate::DetectorValidatorSpec::Uuid { .. }
                | crate::DetectorValidatorSpec::PatternShape { .. }
                | crate::DetectorValidatorSpec::HexHash { .. }
                | crate::DetectorValidatorSpec::LuhnChecksum { .. }
                | crate::DetectorValidatorSpec::Jwt { .. } => {}
                _ => {
                    issues.push(QualityIssue::Error(format!(
                        "validators[{index}].prefixes must not be empty"
                    )));
                }
            }
        }
        for prefix in prefixes {
            if prefix.is_empty() || !prefix.is_ascii() {
                issues.push(QualityIssue::Error(format!(
                    "validators[{index}] prefix {prefix:?} must be non-empty ASCII"
                )));
            }
            if !claimed_prefixes.insert(prefix) {
                issues.push(QualityIssue::Error(format!(
                    "detector validators claim prefix {prefix:?} more than once"
                )));
            }
        }

        if let Some(floor) = validator.confidence_floor() {
            if !floor.is_finite() || !(0.0..=1.0).contains(&floor) {
                issues.push(QualityIssue::Error(format!(
                    "validators[{index}].confidence_floor must be finite and in [0.0, 1.0], found {floor}"
                )));
            }
        }

        match validator {
            crate::DetectorValidatorSpec::Crc32Base62 {
                entropy_len,
                checksum_len,
                ..
            } => {
                if *entropy_len == 0 || *checksum_len == 0 {
                    issues.push(QualityIssue::Error(format!(
                        "validators[{index}] CRC32 entropy_len and checksum_len must both be greater than zero"
                    )));
                }
            }
            crate::DetectorValidatorSpec::GithubFineGrainedCrc32 {
                left_len,
                right_len,
                checksum_len,
                ..
            } => {
                if *left_len == 0 || *checksum_len == 0 || *right_len <= *checksum_len {
                    issues.push(QualityIssue::Error(format!(
                        "validators[{index}] fine-grained lengths require left_len > 0 and right_len > checksum_len > 0"
                    )));
                }
            }
            crate::DetectorValidatorSpec::Base64Payload {
                min_encoded_len,
                max_encoded_len,
                min_decoded_len,
                ..
            } => {
                if *min_encoded_len == 0
                    || *max_encoded_len < *min_encoded_len
                    || *min_decoded_len == 0
                {
                    issues.push(QualityIssue::Error(format!(
                        "validators[{index}] base64 lengths require 0 < min_encoded_len <= max_encoded_len and min_decoded_len > 0"
                    )));
                }
            }
            crate::DetectorValidatorSpec::PatternShape { .. } => {
                if spec.patterns.is_empty() {
                    issues.push(QualityIssue::Error(format!(
                        "validators[{index}] pattern-shape requires at least one detector pattern"
                    )));
                }
            }
            crate::DetectorValidatorSpec::Jwt { .. } => {}
            crate::DetectorValidatorSpec::Uuid { .. } => {}
            crate::DetectorValidatorSpec::HexHash { expected_len, .. } => {
                if *expected_len == 0 {
                    issues.push(QualityIssue::Error(format!(
                        "validators[{index}] HexHash expected_len must be greater than zero"
                    )));
                }
            }
            crate::DetectorValidatorSpec::LuhnChecksum {
                min_len, max_len, ..
            } => {
                if *min_len == 0 || *max_len < *min_len {
                    issues.push(QualityIssue::Error(format!(
                        "validators[{index}] LuhnChecksum requires 0 < min_len <= max_len"
                    )));
                }
            }
        }
    }
}

fn validate_identity(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if spec.id.is_empty() {
        issues.push(QualityIssue::Error(
            "detector.id must not be empty; assign a stable detector identifier".to_string(),
        ));
    } else if spec.id.trim() != spec.id {
        issues.push(QualityIssue::Error(
            "detector.id must not contain leading or trailing whitespace; remove the padding"
                .to_string(),
        ));
    }
}

fn validate_decoded_hex_key_material_lengths(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if spec.decoded_hex_key_material_lengths.is_empty() {
        return;
    }
    if spec.kind != DetectorKind::Phase2Generic {
        issues.push(QualityIssue::Error(
            "decoded_hex_key_material_lengths is only valid for kind = \"phase2-generic\"".into(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for &length in &spec.decoded_hex_key_material_lengths {
        if length < 16 || length % 2 != 0 {
            issues.push(QualityIssue::Error(format!(
                "decoded_hex_key_material_lengths value {length} must be an even character count of at least 16"
            )));
        }
        if !seen.insert(length) {
            issues.push(QualityIssue::Error(format!(
                "decoded_hex_key_material_lengths contains duplicate length {length}"
            )));
        }
    }
}

fn validate_canonical_hex_key_material(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if spec.canonical_hex_key_material.is_empty() {
        return;
    }
    let generic_policy = spec.kind == DetectorKind::Phase2Generic;
    let has_assignment_scope = |policy: &CanonicalHexKeyMaterialSpec| {
        !policy.keywords.is_empty()
            || !policy.suffixes.is_empty()
            || !policy.excluded_keywords.is_empty()
    };
    if !generic_policy
        && spec
            .canonical_hex_key_material
            .iter()
            .any(has_assignment_scope)
    {
        issues.push(QualityIssue::Error(
            "keyword- or suffix-scoped canonical_hex_key_material is only valid for kind = \"phase2-generic\"; regex detectors must declare length-only entries because the matched pattern is their anchor".into(),
        ));
    }

    let owned_keywords: std::collections::HashSet<String> = spec
        .keywords
        .iter()
        .filter_map(|keyword| normalize_detector_keyword(keyword))
        .collect();
    let mut seen_pairs = std::collections::HashSet::new();
    let mut seen_regex_lengths = std::collections::HashSet::new();
    for (policy_index, policy) in spec.canonical_hex_key_material.iter().enumerate() {
        if policy.lengths.is_empty() {
            issues.push(QualityIssue::Error(format!(
                "canonical_hex_key_material[{policy_index}].lengths must not be empty"
            )));
        }
        if generic_policy && policy.keywords.is_empty() && policy.suffixes.is_empty() {
            issues.push(QualityIssue::Error(format!(
                "phase2-generic canonical_hex_key_material[{policy_index}] must declare keywords or suffixes"
            )));
        }
        let mut seen_lengths = std::collections::HashSet::new();
        for &length in &policy.lengths {
            if length < 16 || length % 2 != 0 {
                issues.push(QualityIssue::Error(format!(
                    "canonical_hex_key_material[{policy_index}] length {length} must be an even character count of at least 16"
                )));
            }
            if !seen_lengths.insert(length) {
                issues.push(QualityIssue::Error(format!(
                    "canonical_hex_key_material[{policy_index}] contains duplicate length {length}"
                )));
            }
            if !generic_policy && !seen_regex_lengths.insert(length) {
                issues.push(QualityIssue::Error(format!(
                    "canonical_hex_key_material repeats regex-detector length {length} across policies"
                )));
            }
        }
        let mut seen_keywords = std::collections::HashSet::new();
        for keyword in &policy.keywords {
            let Some(normalized) = normalize_detector_keyword(keyword) else {
                issues.push(QualityIssue::Error(format!(
                    "canonical_hex_key_material[{policy_index}] keyword {keyword:?} must contain ASCII alphanumerics with only `_`, `-`, or `.` separators"
                )));
                continue;
            };
            if !seen_keywords.insert(normalized.clone()) {
                issues.push(QualityIssue::Error(format!(
                    "canonical_hex_key_material[{policy_index}] contains duplicate normalized keyword {normalized:?}"
                )));
            }
            if !owned_keywords.contains(&normalized) {
                issues.push(QualityIssue::Error(format!(
                    "canonical_hex_key_material[{policy_index}] keyword {keyword:?} must also appear in detector.keywords"
                )));
            }
            for &length in &policy.lengths {
                if !seen_pairs.insert((normalized.clone(), length)) {
                    issues.push(QualityIssue::Error(format!(
                        "canonical_hex_key_material repeats keyword {keyword:?} at length {length} across policies"
                    )));
                }
            }
        }
        let mut seen_suffixes = std::collections::HashSet::new();
        for suffix in &policy.suffixes {
            let Some(normalized) = normalize_detector_keyword(suffix) else {
                issues.push(QualityIssue::Error(format!(
                    "canonical_hex_key_material[{policy_index}] suffix {suffix:?} must contain ASCII alphanumerics with only `_`, `-`, or `.` separators"
                )));
                continue;
            };
            if normalized.is_empty() {
                issues.push(QualityIssue::Error(format!(
                    "canonical_hex_key_material[{policy_index}] suffix {suffix:?} must not be empty"
                )));
            }
            if !seen_suffixes.insert(normalized) {
                issues.push(QualityIssue::Error(format!(
                    "canonical_hex_key_material[{policy_index}] contains duplicate normalized suffix {suffix:?}"
                )));
            }
        }
        let mut seen_exclusions = std::collections::HashSet::new();
        for excluded in &policy.excluded_keywords {
            let Some(normalized) = normalize_detector_keyword(excluded) else {
                issues.push(QualityIssue::Error(format!(
                    "canonical_hex_key_material[{policy_index}] excluded keyword {excluded:?} must contain ASCII alphanumerics with only `_`, `-`, or `.` separators"
                )));
                continue;
            };
            if !seen_exclusions.insert(normalized) {
                issues.push(QualityIssue::Error(format!(
                    "canonical_hex_key_material[{policy_index}] contains duplicate excluded keyword {excluded:?}"
                )));
            }
        }
    }
}

fn normalize_detector_keyword(keyword: &str) -> Option<String> {
    let mut normalized = String::with_capacity(keyword.len());
    for byte in keyword.bytes() {
        if byte.is_ascii_alphanumeric() {
            normalized.push(byte.to_ascii_lowercase() as char);
        } else if !matches!(byte, b'_' | b'-' | b'.') {
            return None;
        }
    }
    (!normalized.is_empty()).then_some(normalized)
}

fn validate_simdsieve_prefixes(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    let mut seen = std::collections::HashSet::new();
    for (index, prefix) in spec.simdsieve_prefixes.iter().enumerate() {
        if prefix.is_empty() {
            issues.push(QualityIssue::Error(format!(
                "simdsieve_prefixes[{index}] must not be empty"
            )));
        } else if !prefix.is_ascii() {
            issues.push(QualityIssue::Error(format!(
                "simdsieve_prefixes[{index}] must be ASCII because simdsieve performs byte-prefix matching"
            )));
        }
        if !seen.insert(prefix) {
            issues.push(QualityIssue::Error(format!(
                "simdsieve_prefixes contains duplicate literal {prefix:?}"
            )));
        }
    }
}

/// `min_confidence` is a probability in `[0.0, 1.0]`. It is a bare `Option<f64>`
/// with no serde bound, so a typo'd value parses cleanly and then silently
/// breaks the gate: `< 0.0` always clears the confidence floor (every candidate
/// surfaces), `> 1.0` can never clear it (the detector never fires), and `NaN`
/// makes every comparison false. Reject anything outside the closed unit range
/// (a `RangeInclusive::contains` check is false for `NaN`, so NaN is caught too).
fn validate_thresholds(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if !(0.0..=1.0).contains(&spec.ml.weight) {
        issues.push(QualityIssue::Error(format!(
            "ml.weight {} is out of range; detector model weight must be finite and in [0.0, 1.0]",
            spec.ml.weight
        )));
    }
    if spec.ml.context_radius_lines > 64 {
        issues.push(QualityIssue::Error(format!(
            "ml.context_radius_lines {} exceeds the bounded maximum of 64",
            spec.ml.context_radius_lines
        )));
    }
    let owns_entropy = spec.owns_entropy_policy();
    match spec.match_confidence {
        None => issues.push(QualityIssue::Error(
            "detector must declare match_confidence; scanner-wide match scoring defaults are not permitted"
                .into(),
        )),
        Some(confidence) => {
            if let Err(error) = confidence.validate() {
                issues.push(QualityIssue::Error(format!(
                    "match_confidence is invalid: {error}"
                )));
            }
            if owns_entropy {
                if confidence.named_anchor_floor.is_some() {
                    issues.push(QualityIssue::Error(
                        "generic entropy owners must omit match_confidence.named_anchor_floor because their regex candidates do not receive the named-detector lift"
                            .into(),
                    ));
                }
                if confidence.low_promise_confidence.is_none() {
                    issues.push(QualityIssue::Error(
                        "generic entropy owners must declare match_confidence.low_promise_confidence"
                            .into(),
                    ));
                }
            } else {
                if confidence.named_anchor_floor.is_none() {
                    issues.push(QualityIssue::Error(
                        "named detectors must declare match_confidence.named_anchor_floor"
                            .into(),
                    ));
                }
                if confidence.low_promise_confidence.is_some() {
                    issues.push(QualityIssue::Error(
                        "named detectors must omit match_confidence.low_promise_confidence because the promise gate cannot replace service-owned evidence"
                            .into(),
                    ));
                }
            }
        }
    }
    if owns_entropy && spec.ml.entropy_mode == crate::DetectorMlMode::Disabled {
        issues.push(QualityIssue::Error(
            "an active entropy-policy owner must declare a non-disabled ml.entropy_mode"
                .to_string(),
        ));
    }
    if !owns_entropy && spec.ml.entropy_mode != crate::DetectorMlMode::Disabled {
        issues.push(QualityIssue::Error(
            "ml.entropy_mode is only valid for a detector that owns entropy policy".to_string(),
        ));
    }
    for (name, value) in [
        ("min_len", spec.min_len),
        ("max_len", spec.max_len),
        ("keyword_free_min_len", spec.keyword_free_min_len),
    ] {
        if value == Some(0) {
            issues.push(QualityIssue::Error(format!(
                "{name} must be greater than 0 when present; use omission to inherit the path default"
            )));
        }
    }
    if let (Some(min_len), Some(max_len)) = (spec.min_len, spec.max_len) {
        if min_len > max_len {
            issues.push(QualityIssue::Error(format!(
                "min_len {min_len} exceeds max_len {max_len}"
            )));
        }
    }
    if spec.max_len.is_some_and(|max_len| max_len < 8) {
        issues.push(QualityIssue::Error(
            "max_len must be at least the generic assignment path minimum of 8".to_string(),
        ));
    }
    if spec.max_len.is_some() && !spec.owns_entropy_policy() {
        issues.push(QualityIssue::Error(
            "max_len is only valid for detectors that own generic entropy policy".to_string(),
        ));
    }
    if let Some(mc) = spec.min_confidence {
        if !(0.0..=1.0).contains(&mc) {
            issues.push(QualityIssue::Error(format!(
                "min_confidence {mc} is out of range; confidence is a probability in [0.0, 1.0] \
                 (outside it silently breaks the gate: < 0 always passes, > 1 never fires, NaN is undefined)"
            )));
        }
    }
    if let Some(bound) = spec.bpe_max_bytes_per_token {
        if !bound.is_finite() || bound <= 0.0 {
            issues.push(QualityIssue::Error(format!(
                "bpe_max_bytes_per_token {bound} must be finite and greater than 0; \
                 zero or a negative value suppresses every candidate and NaN/inf makes the gate undefined"
            )));
        }
    }
    if spec.bpe_enabled == Some(false) && spec.bpe_max_bytes_per_token.is_some() {
        issues.push(QualityIssue::Error(
            "bpe_enabled = false conflicts with bpe_max_bytes_per_token; remove the ceiling when token efficiency is disabled"
                .into(),
        ));
    }
    if !spec.entropy_roles.is_empty() && !spec.owns_entropy_policy() {
        issues.push(QualityIssue::Error(
            "entropy_roles require a detector that owns a complete entropy policy".into(),
        ));
    }
    let mut entropy_roles = std::collections::HashSet::new();
    for role in &spec.entropy_roles {
        if !entropy_roles.insert(*role) {
            issues.push(QualityIssue::Error(format!(
                "entropy_roles contains duplicate role {:?}",
                role.as_str()
            )));
        }
    }
    for (name, value) in [
        ("entropy_high", spec.entropy_high),
        ("entropy_low", spec.entropy_low),
        ("entropy_very_high", spec.entropy_very_high),
        (
            "sensitive_path_entropy_very_high",
            spec.sensitive_path_entropy_very_high,
        ),
    ] {
        let Some(score) = value else {
            continue;
        };
        if !score.is_finite() || !(0.0..=8.0).contains(&score) {
            issues.push(QualityIssue::Error(format!(
                "{name} must be a finite Shannon entropy score in [0.0, 8.0], found {score}"
            )));
        }
    }
    if let (Some(low), Some(high)) = (spec.entropy_low, spec.entropy_high) {
        if low > high {
            issues.push(QualityIssue::Error(format!(
                "entropy_low {low} must not exceed entropy_high {high}"
            )));
        }
    }
    if let (Some(high), Some(very_high)) = (spec.entropy_high, spec.entropy_very_high) {
        if high > very_high {
            issues.push(QualityIssue::Error(format!(
                "entropy_high {high} must not exceed entropy_very_high {very_high}"
            )));
        }
    }
    if let Some(plausibility) = spec.plausibility {
        for (name, score) in [
            (
                "plausibility.mixed_alnum_floor",
                plausibility.mixed_alnum_floor,
            ),
            (
                "plausibility.symbolic_entropy_floor",
                plausibility.symbolic_entropy_floor,
            ),
            (
                "plausibility.second_half_entropy_floor",
                plausibility.second_half_entropy_floor,
            ),
            (
                "plausibility.isolated_mixed_entropy_floor",
                plausibility.isolated_mixed_entropy_floor,
            ),
            (
                "plausibility.leading_slash_base64_entropy_floor",
                plausibility.leading_slash_base64_entropy_floor,
            ),
        ] {
            if !score.is_finite() || !(0.0..=8.0).contains(&score) {
                issues.push(QualityIssue::Error(format!(
                    "{name} must be a finite Shannon entropy score in [0.0, 8.0], found {score}"
                )));
            }
        }
        if let Some(margin) = plausibility.keyword_free_operator_margin {
            if !margin.is_finite() || !(0.0..=8.0).contains(&margin) {
                issues.push(QualityIssue::Error(format!(
                    "plausibility.keyword_free_operator_margin must be finite and in [0.0, 8.0], found {margin}"
                )));
            }
        }
        if plausibility.mixed_alnum_min_len == 0 {
            issues.push(QualityIssue::Error(
                "plausibility.mixed_alnum_min_len must be greater than zero".into(),
            ));
        }
        for (name, length) in [
            (
                "plausibility.second_half_min_len",
                plausibility.second_half_min_len,
            ),
            (
                "plausibility.unique_chars_min_len",
                plausibility.unique_chars_min_len,
            ),
            (
                "plausibility.min_unique_chars",
                plausibility.min_unique_chars,
            ),
            (
                "plausibility.unanchored_hex_max_len",
                plausibility.unanchored_hex_max_len,
            ),
            (
                "plausibility.identical_char_max_len",
                plausibility.identical_char_max_len,
            ),
            (
                "plausibility.structured_dotted_min_len",
                plausibility.structured_dotted_min_len,
            ),
            (
                "plausibility.isolated_symbolic_min_len",
                plausibility.isolated_symbolic_min_len,
            ),
            (
                "plausibility.isolated_symbolic_min_symbols",
                plausibility.isolated_symbolic_min_symbols,
            ),
            (
                "plausibility.isolated_alpha_only_min_symbols",
                plausibility.isolated_alpha_only_min_symbols,
            ),
            (
                "plausibility.source_type_name_max_len",
                plausibility.source_type_name_max_len,
            ),
            (
                "plausibility.source_type_name_min_uppercase",
                plausibility.source_type_name_min_uppercase,
            ),
            (
                "plausibility.url_path_high_entropy_min_len",
                plausibility.url_path_high_entropy_min_len,
            ),
            (
                "plausibility.isolated_colon_left_min_len",
                plausibility.isolated_colon_left_min_len,
            ),
            (
                "plausibility.isolated_colon_right_min_len",
                plausibility.isolated_colon_right_min_len,
            ),
            (
                "plausibility.leading_slash_base64_min_len",
                plausibility.leading_slash_base64_min_len,
            ),
        ] {
            if length == 0 {
                issues.push(QualityIssue::Error(format!(
                    "{name} must be greater than zero"
                )));
            }
        }
        if !plausibility.isolated_alpha_only_min_alpha_ratio.is_finite()
            || !(0.0..=1.0).contains(&plausibility.isolated_alpha_only_min_alpha_ratio)
            || plausibility.isolated_alpha_only_min_alpha_ratio == 0.0
        {
            issues.push(QualityIssue::Error(format!(
                "plausibility.isolated_alpha_only_min_alpha_ratio must be finite and in (0.0, 1.0], found {}",
                plausibility.isolated_alpha_only_min_alpha_ratio
            )));
        }
        if !plausibility.min_alnum_ratio.is_finite()
            || !(0.0..=1.0).contains(&plausibility.min_alnum_ratio)
            || plausibility.min_alnum_ratio == 0.0
        {
            issues.push(QualityIssue::Error(format!(
                "plausibility.min_alnum_ratio must be finite and in (0.0, 1.0], found {}",
                plausibility.min_alnum_ratio
            )));
        }
        if plausibility.source_type_name_min_uppercase > plausibility.source_type_name_max_len {
            issues.push(QualityIssue::Error(format!(
                "plausibility.source_type_name_min_uppercase ({}) must not exceed plausibility.source_type_name_max_len ({})",
                plausibility.source_type_name_min_uppercase,
                plausibility.source_type_name_max_len
            )));
        }
        if plausibility.min_unique_chars > plausibility.unique_chars_min_len {
            issues.push(QualityIssue::Error(format!(
                "plausibility.min_unique_chars ({}) must not exceed plausibility.unique_chars_min_len ({})",
                plausibility.min_unique_chars, plausibility.unique_chars_min_len
            )));
        }
    }
    if let (Some(very_high), Some(sensitive)) = (
        spec.entropy_very_high,
        spec.sensitive_path_entropy_very_high,
    ) {
        if sensitive > very_high {
            issues.push(QualityIssue::Error(format!(
                "sensitive_path_entropy_very_high {sensitive} must not exceed entropy_very_high {very_high}; sensitive paths may lower the keyword-free bar, never raise it"
            )));
        }
    }
    let entropy_owner = spec.owns_entropy_policy();
    let has_weak_pattern = spec.patterns.iter().any(|pattern| pattern.weak_anchor);
    if spec.weak_anchor && has_weak_pattern {
        issues.push(QualityIssue::Error(
            "detector weak_anchor=true already applies to every pattern; remove redundant pattern weak_anchor flags"
                .into(),
        ));
    }
    if spec.weak_anchor || has_weak_pattern {
        if spec.entropy_high.is_none() {
            issues.push(QualityIssue::Error(
                "weak_anchor detectors and patterns must declare entropy_high in their own detector TOML".into(),
            ));
        }
        if spec.entropy_floor.is_empty() {
            issues.push(QualityIssue::Error(
                "weak_anchor detectors and patterns must declare entropy_floor in their own detector TOML"
                    .into(),
            ));
        }
    }
    if entropy_owner {
        for (field, present) in [
            ("entropy_high", spec.entropy_high.is_some()),
            ("entropy_low", spec.entropy_low.is_some()),
            ("entropy_very_high", spec.entropy_very_high.is_some()),
            (
                "sensitive_path_entropy_very_high",
                spec.sensitive_path_entropy_very_high.is_some(),
            ),
            ("[detector.plausibility]", spec.plausibility.is_some()),
            ("keyword_free_min_len", spec.keyword_free_min_len.is_some()),
            ("min_len", spec.min_len.is_some()),
            ("max_len", spec.max_len.is_some()),
            (
                "entropy_policy_priority",
                spec.entropy_policy_priority.is_some(),
            ),
        ] {
            if !present {
                issues.push(QualityIssue::Error(format!(
                    "active entropy owner must declare {field} in its detector TOML; runtime fallback policy is forbidden"
                )));
            }
        }
        if spec.entropy_shapes.is_empty() {
            issues.push(QualityIssue::Error(
                "active entropy owner must declare detector.entropy_shapes in its detector TOML"
                    .into(),
            ));
        }
        if spec.entropy_floor.is_empty() {
            issues.push(QualityIssue::Error(
                "active entropy owner must declare entropy_floor in its detector TOML".into(),
            ));
        }
        if spec.bpe_enabled.is_none() {
            issues.push(QualityIssue::Error(
                "active entropy owner must declare bpe_enabled in its detector TOML".into(),
            ));
        }
        if spec.bpe_enabled != Some(false) && spec.bpe_max_bytes_per_token.is_none() {
            issues.push(QualityIssue::Error(
                "active entropy owner must declare bpe_max_bytes_per_token or bpe_enabled = false in its detector TOML"
                    .into(),
            ));
        }
    }
    let owns_keyword_free = spec
        .entropy_roles
        .contains(&crate::EntropyDetectionRole::KeywordFree);
    let keyword_free_operator_margin = spec
        .plausibility
        .and_then(|policy| policy.keyword_free_operator_margin);
    match (owns_keyword_free, keyword_free_operator_margin) {
        (true, None) => issues.push(QualityIssue::Error(
            "the detector claiming entropy role `keyword-free` must declare plausibility.keyword_free_operator_margin"
                .into(),
        )),
        (false, Some(_)) => issues.push(QualityIssue::Error(
            "plausibility.keyword_free_operator_margin is valid only on the detector claiming entropy role `keyword-free`"
                .into(),
        )),
        _ => {}
    }
    if entropy_owner && spec.entropy_fallback.is_none() {
        issues.push(QualityIssue::Error(
            "active entropy owner must declare entropy_fallback metadata; omission would make synthetic finding identity ambiguous".into(),
        ));
    }
    if entropy_owner && spec.entropy_fallback_confidence.is_none() {
        issues.push(QualityIssue::Error(
            "active entropy owner must declare entropy_fallback_confidence; omission would leave detector confidence in scanner literals".into(),
        ));
    }
    if entropy_owner && spec.generic_assignment_confidence.is_none() {
        issues.push(QualityIssue::Error(
            "active entropy owner must declare generic_assignment_confidence; omission would leave generic assignment scoring in scanner literals".into(),
        ));
    }
    if let Some(confidence) = spec.entropy_fallback_confidence {
        if !entropy_owner {
            issues.push(QualityIssue::Error(
                "entropy_fallback_confidence requires an active detector-owned entropy policy"
                    .into(),
            ));
        }
        if let Err(error) = confidence.validate() {
            issues.push(QualityIssue::Error(format!(
                "entropy_fallback_confidence is invalid: {error}"
            )));
        }
    }
    if let Some(confidence) = spec.generic_assignment_confidence {
        if !entropy_owner {
            issues.push(QualityIssue::Error(
                "generic_assignment_confidence requires an active detector-owned entropy policy"
                    .into(),
            ));
        }
        if let Err(error) = confidence.validate() {
            issues.push(QualityIssue::Error(format!(
                "generic_assignment_confidence is invalid: {error}"
            )));
        }
    }
    if let Some(metadata) = &spec.entropy_fallback {
        if !entropy_owner {
            issues.push(QualityIssue::Error(
                "entropy_fallback requires an active detector-owned entropy policy".into(),
            ));
        }
        if !metadata.id.strip_prefix("entropy-").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        }) {
            issues.push(QualityIssue::Error(format!(
                "entropy_fallback.id {:?} must use a lowercase entropy- namespace id",
                metadata.id
            )));
        }
        if metadata.name.trim().is_empty() {
            issues.push(QualityIssue::Error(
                "entropy_fallback.name must not be empty".into(),
            ));
        }
        if metadata.service.trim().is_empty() {
            issues.push(QualityIssue::Error(
                "entropy_fallback.service must not be empty".into(),
            ));
        }
    }
    if !spec.entropy_shapes.is_empty() && !entropy_owner {
        issues.push(QualityIssue::Error(
            "entropy_shapes require an active detector-owned entropy policy".into(),
        ));
    }
    if spec.entropy_shapes.len() > 1 {
        issues.push(QualityIssue::Error(format!(
            "active entropy policy accepts exactly one detector.entropy_shapes entry, found {}",
            spec.entropy_shapes.len()
        )));
    }
    let mut shape_signatures: Vec<(crate::spec::ShapeCharset, Option<(usize, usize, char)>)> =
        Vec::new();
    for (index, shape) in spec.entropy_shapes.iter().enumerate() {
        let signature = (
            shape.charset,
            shape
                .grouping
                .map(|g| (g.group_count, g.group_length, g.separator)),
        );
        if shape_signatures.contains(&signature) {
            issues.push(QualityIssue::Error(format!(
                "entropy_shapes[{index}] duplicates an earlier shape's charset and grouping"
            )));
        }
        shape_signatures.push(signature);
        if !shape.entropy_floor.is_finite() || !(0.0..=8.0).contains(&shape.entropy_floor) {
            issues.push(QualityIssue::Error(format!(
                "entropy_shapes[{index}].entropy_floor must be finite and in [0.0, 8.0], found {}",
                shape.entropy_floor
            )));
        }
        if shape.special_min_length == 0 {
            issues.push(QualityIssue::Error(format!(
                "entropy_shapes[{index}].special_min_length must be greater than 0"
            )));
        }
        if shape.require_mixed_case && shape.charset == crate::spec::ShapeCharset::LowerAlnum {
            issues.push(QualityIssue::Error(format!(
                "entropy_shapes[{index}].require_mixed_case is impossible with charset lower-alnum"
            )));
        }
        if shape.require_non_hex_alpha && shape.charset == crate::spec::ShapeCharset::Hex {
            issues.push(QualityIssue::Error(format!(
                "entropy_shapes[{index}].require_non_hex_alpha is impossible with charset hex"
            )));
        }
        if shape.require_group_alpha_digit && shape.grouping.is_none() {
            issues.push(QualityIssue::Error(format!(
                "entropy_shapes[{index}].require_group_alpha_digit requires grouping"
            )));
        }
        if let Some(grouping) = shape.grouping {
            if grouping.group_count == 0 || grouping.group_length == 0 {
                issues.push(QualityIssue::Error(format!(
                    "entropy_shapes[{index}] grouping.group_count and group_length must both be greater than 0"
                )));
                continue;
            }
            let derived_length = grouping
                .group_count
                .checked_mul(grouping.group_length)
                .and_then(|length| {
                    length.checked_add(
                        grouping
                            .group_count
                            .saturating_sub(1)
                            .saturating_mul(grouping.separator.len_utf8()),
                    )
                });
            let Some(derived_length) = derived_length else {
                issues.push(QualityIssue::Error(format!(
                    "entropy_shapes[{index}] grouping overflows the derived candidate length"
                )));
                continue;
            };
            if shape.special_min_length > derived_length {
                issues.push(QualityIssue::Error(format!(
                    "entropy_shapes[{index}].special_min_length must be in 1..={derived_length}, found {}",
                    shape.special_min_length
                )));
            }
        }
    }
}

fn validate_entropy_floor(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if spec.entropy_floor.is_empty() {
        return;
    }
    let last = spec.entropy_floor.len() - 1;
    let mut previous_max = 0usize;
    for (index, bucket) in spec.entropy_floor.iter().enumerate() {
        if !bucket.floor.is_finite() || !(0.0..=8.0).contains(&bucket.floor) {
            issues.push(QualityIssue::Error(format!(
                "entropy_floor bucket {index} floor must be finite and in [0.0, 8.0], found {}",
                bucket.floor
            )));
        }
        if index < last && bucket.max_len.is_none() {
            issues.push(QualityIssue::Error(format!(
                "entropy_floor bucket {index} is an early catch-all; only the final bucket may omit max_len"
            )));
        }
        if index == last && bucket.max_len.is_some() {
            issues.push(QualityIssue::Error(
                "entropy_floor final bucket must omit max_len so longer candidates cannot bypass the floor"
                    .into(),
            ));
        }
        if let Some(max_len) = bucket.max_len {
            if max_len <= previous_max {
                issues.push(QualityIssue::Error(format!(
                    "entropy_floor max_len values must strictly increase from a positive length; found {max_len} after {previous_max}"
                )));
            }
            previous_max = max_len;
        }
    }
}

fn validate_credential_shape(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if let Some(shape) = &spec.credential_shape {
        if let Err(error) = shape.validate(&spec.id) {
            issues.push(QualityIssue::Error(error));
        }
    }
}

fn validate_detector_allowlists(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    for (field, patterns) in [
        ("allowlist_paths", &spec.allowlist_paths),
        ("allowlist_values", &spec.allowlist_values),
        (
            "source_admission.path_patterns",
            &spec.source_admission.path_patterns,
        ),
    ] {
        let mut first_index_by_pattern = HashMap::new();
        for (index, pattern) in patterns.iter().enumerate() {
            if pattern.trim().is_empty() {
                issues.push(QualityIssue::Error(format!(
                    "detector {:?} {field}[{index}] must not be empty or whitespace-only",
                    spec.id
                )));
                continue;
            }
            match first_index_by_pattern.entry(pattern.as_str()) {
                Entry::Occupied(first) => issues.push(QualityIssue::Error(format!(
                    "detector {:?} {field}[{index}] duplicates {field}[{}]",
                    spec.id,
                    first.get()
                ))),
                Entry::Vacant(slot) => {
                    slot.insert(index);
                }
            }
            if let Err(error) = regex::Regex::new(pattern) {
                issues.push(QualityIssue::Error(format!(
                    "detector {:?} {field}[{index}] is not a valid regex ({pattern:?}): {error}",
                    spec.id
                )));
            }
        }
    }

    let mut first_index_by_stopword = HashMap::new();
    for (index, stopword) in spec.stopwords.iter().enumerate() {
        if stopword.trim().is_empty() {
            issues.push(QualityIssue::Error(format!(
                "detector {:?} stopwords[{index}] must not be empty or whitespace-only",
                spec.id
            )));
            continue;
        }
        let normalized = stopword.to_ascii_lowercase();
        match first_index_by_stopword.entry(normalized) {
            Entry::Occupied(first) => issues.push(QualityIssue::Error(format!(
                "detector {:?} stopwords[{index}] duplicates stopwords[{}] under case-insensitive matching",
                spec.id,
                first.get()
            ))),
            Entry::Vacant(slot) => {
                slot.insert(index);
            }
        }
    }
    let mut first_marker_index = HashMap::new();
    for (index, marker) in spec.public_identifier_assignment_markers.iter().enumerate() {
        if marker.is_empty()
            || !marker.is_ascii()
            || marker.bytes().any(|byte| byte.is_ascii_lowercase())
        {
            issues.push(QualityIssue::Error(format!(
                "detector {:?} public_identifier_assignment_markers[{index}] must be non-empty uppercase ASCII because runtime matching is allocation-free ASCII-insensitive",
                spec.id
            )));
            continue;
        }
        match first_marker_index.entry(marker.as_str()) {
            Entry::Occupied(first) => issues.push(QualityIssue::Error(format!(
                "detector {:?} public_identifier_assignment_markers[{index}] duplicates public_identifier_assignment_markers[{}]",
                spec.id,
                first.get()
            ))),
            Entry::Vacant(slot) => {
                slot.insert(index);
            }
        }
    }
    let mut source_types = HashSet::new();
    for (index, source_type) in spec.source_admission.source_types.iter().enumerate() {
        if source_type.trim().is_empty() {
            issues.push(QualityIssue::Error(format!(
                "detector {:?} source_admission.source_types[{index}] must not be empty",
                spec.id
            )));
        } else if !source_types.insert(source_type) {
            issues.push(QualityIssue::Error(format!(
                "detector {:?} source_admission.source_types[{index}] is duplicated",
                spec.id
            )));
        }
    }
    let mut extensions = HashSet::new();
    for (index, extension) in spec.source_admission.file_extensions.iter().enumerate() {
        if extension.is_empty()
            || !extension.is_ascii()
            || extension.starts_with('.')
            || extension.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            issues.push(QualityIssue::Error(format!(
                "detector {:?} source_admission.file_extensions[{index}] must be lowercase ASCII without a leading dot",
                spec.id
            )));
        } else if !extensions.insert(extension) {
            issues.push(QualityIssue::Error(format!(
                "detector {:?} source_admission.file_extensions[{index}] is duplicated",
                spec.id
            )));
        }
    }
}

fn validate_patterns_present(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    match spec.kind {
        // A phase-1 regex detector is defined by its anchors (no patterns is an error).
        DetectorKind::Regex => {
            if spec.patterns.is_empty() {
                issues.push(QualityIssue::Error("no patterns defined".into()));
            }
        }
        // A phase-2 generic bridge is defined by keywords + entropy_floor.
        // Optional patterns add strongly structured envelopes without creating
        // a duplicate detector owner; keywords remain required for the
        // shapeless phase-2 path.
        DetectorKind::Phase2Generic => {
            if spec.keywords.is_empty() {
                issues.push(QualityIssue::Error(
                    "phase2-generic detector must define keywords (its only pre-filter)".into(),
                ));
            }
        }
    }
}

fn validate_regexes<'a>(
    spec: &'a DetectorSpec,
    issues: &mut Vec<QualityIssue>,
    regex_cache: &mut RegexAstCache<'a>,
) {
    for (i, pat) in spec.patterns.iter().enumerate() {
        validate_regex_definition(RegexKind::Pattern, i, &pat.regex, issues, regex_cache);
    }
}

fn validate_keywords(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if spec.keywords.is_empty() {
        issues.push(QualityIssue::Warning(
            "no keywords defined - pattern may produce false positives".into(),
        ));
        return;
    }
    for (index, keyword) in spec.keywords.iter().enumerate() {
        if keyword.is_empty() {
            issues.push(QualityIssue::Error(format!(
                "keyword {index} is empty; remove it or declare a non-empty detector-owned context literal"
            )));
        }
    }
}

fn validate_pattern_groups<'a>(
    spec: &'a DetectorSpec,
    issues: &mut Vec<QualityIssue>,
    regex_cache: &mut RegexAstCache<'a>,
) {
    for (i, pat) in spec.patterns.iter().enumerate() {
        let Some(group) = pat.group else {
            continue;
        };
        let Ok(ast) = regex_cache.parse(&pat.regex) else {
            continue; // LAW10: invalid regex already emits a QualityIssue::Error; detector load fails closed, recall-safe
        };
        let captures = ast_captures_len(ast);
        if group >= captures {
            issues.push(QualityIssue::Error(format!(
                "pattern {i} capture group {group} is out of range; regex has {} capture groups \
                 (valid group indexes are 0..{})",
                captures.saturating_sub(1),
                captures.saturating_sub(1)
            )));
        }
    }
}

fn validate_pattern_specificity<'a>(
    spec: &'a DetectorSpec,
    issues: &mut Vec<QualityIssue>,
    regex_cache: &mut RegexAstCache<'a>,
) {
    for (i, pat) in spec.patterns.iter().enumerate() {
        let has_prefix = has_literal_prefix(regex_cache, &pat.regex, 3);
        let has_group = pat.group.is_some();
        let is_pure_charclass = is_pure_character_class(regex_cache, &pat.regex);

        if is_pure_charclass && !has_group {
            issues.push(QualityIssue::Error(format!(
                "pattern {} is a pure character class ({}) - too broad without context anchoring. \
                 Use a capture group or add a literal prefix.",
                i, pat.regex
            )));
        } else if !has_prefix && !has_group && spec.keywords.is_empty() {
            issues.push(QualityIssue::Warning(format!(
                "pattern {} has no literal prefix and no capture group - may false-positive",
                i
            )));
        }
    }
}

fn validate_companions<'a>(
    spec: &'a DetectorSpec,
    issues: &mut Vec<QualityIssue>,
    regex_cache: &mut RegexAstCache<'a>,
) {
    for (i, companion) in spec.companions.iter().enumerate() {
        if companion.name.trim().is_empty() {
            issues.push(QualityIssue::Error(format!(
                "companion {} name must not be empty",
                i
            )));
        }
        if companion.within_lines > MAX_COMPANION_WITHIN_LINES {
            issues.push(QualityIssue::Error(format!(
                "companion {} within_lines={} exceeds {} search-window limit",
                i, companion.within_lines, MAX_COMPANION_WITHIN_LINES
            )));
        }
        if let Some(within_bytes) = companion.within_bytes {
            if within_bytes == 0 || within_bytes > MAX_COMPANION_WITHIN_BYTES {
                issues.push(QualityIssue::Error(format!(
                    "companion {i} within_bytes={within_bytes} must be in 1..={MAX_COMPANION_WITHIN_BYTES}"
                )));
            }
        }
        if companion.scope == EvidenceScope::SameLine && companion.within_lines != 0 {
            issues.push(QualityIssue::Error(format!(
                "companion {i} scope=same-line requires within_lines=0, found {}",
                companion.within_lines
            )));
        }
        if companion.required && companion.requirement != EvidenceRequirement::Reinforcing {
            issues.push(QualityIssue::Error(format!(
                "companion {i} mixes schema-v2 required=true with typed requirement={:?}; \
                 remove required and keep only the typed requirement",
                companion.requirement
            )));
        }
        if let Some(group) = companion.capture_group {
            if let Ok(regex) = regex::Regex::new(&companion.regex) {
                // LAW10: malformed input fails closed in validation below; this reporting-only branch adds a capture-group diagnostic.
                if group >= regex.captures_len() {
                    issues.push(QualityIssue::Error(format!(
                        "companion {i} capture_group={group} does not exist; regex exposes groups 0..{}",
                        regex.captures_len().saturating_sub(1)
                    )));
                }
            }
        }
        validate_regex_definition(
            RegexKind::Companion,
            i,
            &companion.regex,
            issues,
            regex_cache,
        );
        // A "pure character class" companion (e.g. `[A-Z0-9]{10}` for an
        // Algolia application_id) is acceptable when `within_lines` is small:
        // the positional constraint is itself the contextual anchor. Reject
        // only when the companion permits a wide search radius - at that
        // point the lack of textual context really does over-fire.
        if is_pure_character_class(regex_cache, &companion.regex) {
            if companion.within_lines <= TIGHT_COMPANION_RADIUS {
                issues.push(QualityIssue::Warning(format!(
                    "companion {} regex '{}' is a pure character class; \
                     allowed because within_lines={} ≤ {} (positional anchoring).",
                    i, companion.regex, companion.within_lines, TIGHT_COMPANION_RADIUS
                )));
            } else {
                issues.push(QualityIssue::Error(format!(
                    "companion {} regex '{}' is a pure character class with within_lines={} \
                     (> {}) - the wide search radius needs a literal context anchor",
                    i, companion.regex, companion.within_lines, TIGHT_COMPANION_RADIUS
                )));
            }
        } else if !has_substantial_literal(regex_cache, &companion.regex, 3) {
            issues.push(QualityIssue::Warning(format!(
                "companion {} regex '{}' is too broad - may produce false positives. \
                 Add a context anchor like 'KEY_NAME='.",
                i, companion.regex
            )));
        }
    }
}

fn validate_detector_relations(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    let mut first_by_target: HashMap<&str, (usize, DetectorRelationKind)> = HashMap::new();
    for (index, relation) in spec.detector_relations.iter().enumerate() {
        let target = relation.detector_id.trim();
        if target.is_empty() {
            issues.push(QualityIssue::Error(format!(
                "detector relation {index} target detector_id must not be empty"
            )));
        }
        if target == spec.id {
            issues.push(QualityIssue::Error(format!(
                "detector relation {index} cannot target its owning detector {:?}",
                spec.id
            )));
        }
        if relation.within_lines > MAX_COMPANION_WITHIN_LINES {
            issues.push(QualityIssue::Error(format!(
                "detector relation {index} within_lines={} exceeds {} search-window limit",
                relation.within_lines, MAX_COMPANION_WITHIN_LINES
            )));
        }
        if let Some(within_bytes) = relation.within_bytes {
            if within_bytes > MAX_COMPANION_WITHIN_BYTES {
                issues.push(QualityIssue::Error(format!(
                    "detector relation {index} within_bytes={within_bytes} must be in 0..={MAX_COMPANION_WITHIN_BYTES}"
                )));
            }
        }
        if let Some((first_index, first_kind)) =
            first_by_target.insert(target, (index, relation.kind))
        {
            let detail = if first_kind == relation.kind {
                "duplicates"
            } else {
                "contradicts"
            };
            issues.push(QualityIssue::Error(format!(
                "detector relation {index} {detail} relation {first_index} for target {target:?}; \
                 declare one operation per detector pair"
            )));
        }
    }
}

/// Companion search radius (in lines) below which a pure character-class
/// regex is acceptable. The positional bound provides the context anchor.
const TIGHT_COMPANION_RADIUS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegexKind {
    Pattern,
    Companion,
}

impl RegexKind {
    fn label(self) -> &'static str {
        match self {
            Self::Pattern => "pattern",
            Self::Companion => "companion",
        }
    }
}

fn validate_regex_definition<'a>(
    kind: RegexKind,
    index: usize,
    regex: &'a str,
    issues: &mut Vec<QualityIssue>,
    regex_cache: &mut RegexAstCache<'a>,
) {
    let kind = kind.label();
    // An empty regex is VALID syntax, it parses cleanly and matches the empty
    // string at EVERY position, so a detector carrying one fires on every byte
    // of every file: a catastrophic false-positive flood that the parse check
    // below cannot catch (it compiles fine). Reject it up front, fail closed.
    if regex.is_empty() {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex is empty; an empty pattern matches at every position \
             (a catastrophic false-positive flood), define a real anchor or remove the pattern"
        )));
        return;
    }
    if regex.len() > MAX_REGEX_PATTERN_LEN {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex is too large ({} bytes > {} byte limit)",
            regex.len(),
            MAX_REGEX_PATTERN_LEN
        )));
        return;
    }

    match regex_cache.parse(regex) {
        Ok(ast) => validate_regex_complexity(kind, index, ast, issues),
        Err(error) => issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex does not compile: {error}"
        ))),
    }
}

mod regex_ast;
mod regex_complexity;
mod verify;

use regex_ast::{
    ast_captures_len, has_literal_prefix, has_substantial_literal, is_pure_character_class,
    RegexAstCache,
};
use regex_complexity::validate_regex_complexity;
use verify::validate_verify_spec;
