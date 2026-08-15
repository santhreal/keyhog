//! Pattern-conditioned permission for model-driven confidence reduction.

use std::sync::LazyLock;

use serde::Deserialize;

use crate::candidate_provenance::CandidateChannel;
use crate::types::MlPendingMatch;

const SCHEMA_VERSION: u32 = 1;
const IDENTITY_SCHEMA: &str =
    "detector-corpus-v1:detector-id:pattern-index:candidate-channel:source-role:context-class";
const MAX_ENTRIES: usize = 16_384;
const MAX_DETECTOR_ID_BYTES: usize = 128;
const BLOCKING_SCORE: f64 = 0.4;
const MINIMUM_CLASS_SUPPORT: u64 = 2;
const MINIMUM_RECALL: f64 = 1.0;
const MAXIMUM_BRIER_SCORE: f64 = 0.25;
const MAXIMUM_ECE: f64 = 0.1;
const EMBEDDED_ARTIFACT: &str = include_str!("pattern_calibration.json");

static CALIBRATION: LazyLock<Result<PatternCalibration, String>> =
    LazyLock::new(|| PatternCalibration::parse(EMBEDDED_ARTIFACT));

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArtifact {
    schema_version: u32,
    identity_schema: String,
    model_version: String,
    detector_digest: Option<String>,
    floors: CalibrationFloors,
    entries: Vec<CalibrationEntry>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibrationFloors {
    blocking_score: f64,
    minimum_positive_support: u64,
    minimum_negative_support: u64,
    minimum_recall: f64,
    maximum_brier_score: f64,
    maximum_ece: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibrationEntry {
    detector_id: String,
    pattern_index: u32,
    candidate_channel: String,
    source_role: String,
    context_class: String,
    metrics: CalibrationMetrics,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibrationMetrics {
    f1: f64,
    precision: f64,
    recall: f64,
    recall_at_blocking_floor: f64,
    brier_score: f64,
    ece: f64,
    positive_support: u64,
    negative_support: u64,
}

#[derive(Debug)]
struct PatternCalibration {
    model_version: String,
    detector_digest: Option<u64>,
    floors: CalibrationFloors,
    entries: Vec<CalibrationEntry>,
}

impl PatternCalibration {
    fn parse(raw: &str) -> Result<Self, String> {
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
        let detector_digest = artifact
            .detector_digest
            .as_deref()
            .map(parse_digest)
            .transpose()?;
        if detector_digest.is_none() && !artifact.entries.is_empty() {
            return Err("populated pattern calibration lacks detector_digest".to_owned());
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

    fn allows_lowering(&self, detector_digest: u64, pending: &MlPendingMatch) -> bool {
        if self.detector_digest != Some(detector_digest)
            || self.model_version != crate::ml_scorer::model_version()
        {
            return false;
        }
        let provenance = pending.pending_raw_match.provenance;
        let Some(pattern) = provenance.pattern() else {
            return false;
        };
        if !matches!(provenance.channel(), CandidateChannel::NamedPattern) {
            return false;
        }
        let key = (
            pending.pending_raw_match.detector_id.as_ref(),
            pattern.pattern_index,
            "pattern",
            provenance.source_role().as_str(),
            provenance.context_class().as_str(),
        );
        let Ok(index) = self
            .entries
            .binary_search_by(|entry| entry_key(entry).cmp(&key))
        else {
            return false;
        };
        metrics_meet_floors(self.entries[index].metrics, self.floors)
    }
}

fn entry_key(entry: &CalibrationEntry) -> (&str, u32, &str, &str, &str) {
    (
        entry.detector_id.as_str(),
        entry.pattern_index,
        entry.candidate_channel.as_str(),
        entry.source_role.as_str(),
        entry.context_class.as_str(),
    )
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

fn metrics_meet_floors(metrics: CalibrationMetrics, floors: CalibrationFloors) -> bool {
    metrics.positive_support >= floors.minimum_positive_support
        && metrics.negative_support >= floors.minimum_negative_support
        && metrics.recall >= floors.minimum_recall
        && metrics.recall_at_blocking_floor >= floors.minimum_recall
        && metrics.brier_score <= floors.maximum_brier_score
        && metrics.ece <= floors.maximum_ece
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

pub(crate) fn allows_model_lowering(detector_digest: u64, pending: &MlPendingMatch) -> bool {
    CALIBRATION
        .as_ref()
        .is_ok_and(|calibration| calibration.allows_lowering(detector_digest, pending))
}

pub(crate) fn evaluate_artifact_key(
    raw: &str,
    detector_digest: u64,
    detector_id: &str,
    pattern_index: u32,
    candidate_channel: &str,
    source_role: &str,
    context_class: &str,
) -> Result<bool, String> {
    let calibration = PatternCalibration::parse(raw)?;
    if calibration.detector_digest != Some(detector_digest)
        || calibration.model_version != crate::ml_scorer::model_version()
        || candidate_channel != "pattern"
    {
        return Ok(false);
    }
    let key = (
        detector_id,
        pattern_index,
        candidate_channel,
        source_role,
        context_class,
    );
    Ok(calibration
        .entries
        .binary_search_by(|entry| entry_key(entry).cmp(&key))
        .ok()
        .is_some_and(|index| {
            metrics_meet_floors(calibration.entries[index].metrics, calibration.floors)
        }))
}
