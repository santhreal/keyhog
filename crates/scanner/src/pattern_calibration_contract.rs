//! Shared parser for the persisted pattern-calibration contract.

use serde::Deserialize;

pub(crate) const SCHEMA_VERSION: u32 = 1;
pub(crate) const IDENTITY_SCHEMA: &str =
    "detector-corpus-v1:detector-id:pattern-index:candidate-channel:source-role:context-class";
pub(crate) const MAX_ENTRIES: usize = 16_384;
const MAX_DETECTOR_ID_BYTES: usize = 128;
const BLOCKING_SCORE: f64 = 0.4;
const MINIMUM_CLASS_SUPPORT: u64 = 2;
const MINIMUM_RECALL: f64 = 1.0;
const MAXIMUM_BRIER_SCORE: f64 = 0.25;
const MAXIMUM_ECE: f64 = 0.1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArtifact {
    schema_version: u32,
    identity_schema: String,
    model_version: String,
    detector_digest: NullableDetectorDigest,
    floors: CalibrationFloors,
    entries: Vec<CalibrationEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NullableDetectorDigest {
    Digest(String),
    Null(()),
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CalibrationFloors {
    pub(crate) blocking_score: f64,
    pub(crate) minimum_positive_support: u64,
    pub(crate) minimum_negative_support: u64,
    pub(crate) minimum_recall: f64,
    pub(crate) maximum_brier_score: f64,
    pub(crate) maximum_ece: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CalibrationEntry {
    pub(crate) detector_id: String,
    pub(crate) pattern_index: u32,
    pub(crate) candidate_channel: String,
    pub(crate) source_role: String,
    pub(crate) context_class: String,
    pub(crate) metrics: CalibrationMetrics,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CalibrationMetrics {
    pub(crate) f1: f64,
    pub(crate) precision: f64,
    pub(crate) recall: f64,
    pub(crate) recall_at_blocking_floor: f64,
    pub(crate) brier_score: f64,
    pub(crate) ece: f64,
    pub(crate) positive_support: u64,
    pub(crate) negative_support: u64,
}

#[derive(Debug)]
pub(crate) struct PatternCalibration {
    pub(crate) model_version: String,
    #[allow(dead_code)]
    pub(crate) detector_digest: Option<u64>,
    pub(crate) floors: CalibrationFloors,
    pub(crate) entries: Vec<CalibrationEntry>,
}

impl PatternCalibration {
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        let mut artifact: RawArtifact = serde_json::from_str(raw)
            .map_err(|error| format!("invalid pattern calibration JSON: {error}"))?;
        if artifact.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "unsupported pattern calibration schema {}; expected {SCHEMA_VERSION}",
                artifact.schema_version
            ));
        }
        if artifact.identity_schema != IDENTITY_SCHEMA {
            return Err("stale pattern calibration identity schema".to_owned());
        }
        if !valid_model_version(&artifact.model_version) {
            return Err(
                "pattern calibration model_version must use moe-v1- plus 16 lowercase hex digits"
                    .to_owned(),
            );
        }
        if artifact.entries.len() > MAX_ENTRIES {
            return Err(format!(
                "pattern calibration has {} entries; maximum is {MAX_ENTRIES}",
                artifact.entries.len()
            ));
        }
        validate_floors(artifact.floors)?;
        let detector_digest = match &artifact.detector_digest {
            NullableDetectorDigest::Digest(raw) => Some(parse_digest(raw)?),
            NullableDetectorDigest::Null(()) => None,
        };
        if detector_digest.is_none() && !artifact.entries.is_empty() {
            return Err("populated pattern calibration lacks detector_digest".to_owned());
        }
        if detector_digest.is_some() && artifact.entries.is_empty() {
            return Err("empty pattern calibration must use a null detector_digest".to_owned());
        }
        for entry in &artifact.entries {
            validate_entry(entry)?;
        }
        artifact
            .entries
            .sort_unstable_by(|left, right| entry_key(left).cmp(&entry_key(right)));
        if artifact
            .entries
            .windows(2)
            .any(|pair| entry_key(&pair[0]) == entry_key(&pair[1]))
        {
            return Err("pattern calibration contains a duplicate exact key".to_owned());
        }
        Ok(Self {
            model_version: artifact.model_version,
            detector_digest,
            floors: artifact.floors,
            entries: artifact.entries,
        })
    }
}

pub(crate) fn entry_key(entry: &CalibrationEntry) -> (&str, u32, &str, &str, &str) {
    (
        entry.detector_id.as_str(),
        entry.pattern_index,
        entry.candidate_channel.as_str(),
        entry.source_role.as_str(),
        entry.context_class.as_str(),
    )
}

pub(crate) fn metrics_meet_floors(metrics: CalibrationMetrics, floors: CalibrationFloors) -> bool {
    metrics.positive_support >= floors.minimum_positive_support
        && metrics.negative_support >= floors.minimum_negative_support
        && metrics.recall >= floors.minimum_recall
        && metrics.recall_at_blocking_floor >= floors.minimum_recall
        && metrics.brier_score <= floors.maximum_brier_score
        && metrics.ece <= floors.maximum_ece
}

fn parse_digest(raw: &str) -> Result<u64, String> {
    if raw.len() != 16
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "pattern calibration detector_digest must be 16 lowercase hex digits".to_owned(),
        );
    }
    u64::from_str_radix(raw, 16)
        .map_err(|_| "pattern calibration detector_digest is invalid".to_owned())
}

fn valid_detector_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DETECTOR_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_model_version(value: &str) -> bool {
    value.len() == "moe-v1-".len() + 16
        && value.starts_with("moe-v1-")
        && value["moe-v1-".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_floors(floors: CalibrationFloors) -> Result<(), String> {
    if floors.minimum_positive_support == 0 || floors.minimum_negative_support == 0 {
        return Err(
            "pattern calibration requires positive support floors for both classes".to_owned(),
        );
    }
    for (name, value) in [
        ("blocking_score", floors.blocking_score),
        ("minimum_recall", floors.minimum_recall),
        ("maximum_brier_score", floors.maximum_brier_score),
        ("maximum_ece", floors.maximum_ece),
    ] {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(format!(
                "pattern calibration {name} must be finite and in [0, 1]"
            ));
        }
    }
    if floors.blocking_score.to_bits() != BLOCKING_SCORE.to_bits()
        || floors.minimum_positive_support < MINIMUM_CLASS_SUPPORT
        || floors.minimum_negative_support < MINIMUM_CLASS_SUPPORT
        || floors.minimum_recall < MINIMUM_RECALL
        || floors.maximum_brier_score > MAXIMUM_BRIER_SCORE
        || floors.maximum_ece > MAXIMUM_ECE
    {
        return Err(
            "pattern calibration artifact weakens the serving calibration floors".to_owned(),
        );
    }
    Ok(())
}

fn validate_entry(entry: &CalibrationEntry) -> Result<(), String> {
    if !valid_detector_id(&entry.detector_id) {
        return Err(
            "pattern calibration detector_id must be a bounded lowercase detector slug".to_owned(),
        );
    }
    if entry.candidate_channel != "pattern" {
        return Err("pattern calibration entries must use candidate_channel 'pattern'".to_owned());
    }
    if !valid_source_role(&entry.source_role) {
        return Err(format!(
            "pattern calibration has unknown source_role {:?}",
            entry.source_role
        ));
    }
    if !valid_context_class(&entry.context_class) {
        return Err(format!(
            "pattern calibration has unknown context_class {:?}",
            entry.context_class
        ));
    }
    for (name, value) in [
        ("f1", entry.metrics.f1),
        ("precision", entry.metrics.precision),
        ("recall", entry.metrics.recall),
        (
            "recall_at_blocking_floor",
            entry.metrics.recall_at_blocking_floor,
        ),
        ("brier_score", entry.metrics.brier_score),
        ("ece", entry.metrics.ece),
    ] {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(format!(
                "pattern calibration metric {name} must be finite and in [0, 1]"
            ));
        }
    }
    Ok(())
}

fn valid_source_role(value: &str) -> bool {
    matches!(
        value,
        "structured-assignment-value"
            | "environment-assignment-value"
            | "string-literal"
            | "command-argument-value"
            | "command-option-declaration"
            | "header-value"
            | "url-authority-userinfo"
            | "connection-string"
            | "standalone-token"
            | "pem-block"
            | "regex-rule-definition"
            | "identifier-type-member-name"
            | "prose-documentation"
            | "test-fixture"
            | "generated-vendor-material"
            | "unknown"
    )
}

fn valid_context_class(value: &str) -> bool {
    matches!(
        value,
        "unsupported-context"
            | "required-evidence-missing"
            | "weak-anchor"
            | "generic-detector"
            | "generic-assignment"
            | "entropy-only"
            | "test-fixture"
            | "documentation"
            | "rule-definition"
            | "identifier"
            | "option-declaration"
            | "generated-material"
            | "source-role-mismatch"
            | "vendor-pattern"
            | "structural-grammar"
            | "required-companion"
            | "checksum-valid"
    )
}
