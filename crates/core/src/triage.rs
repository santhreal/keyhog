//! Versioned, redacted triage interchange and derived feedback artifacts.

use crate::{FindingCandidateChannel, FindingProvenance};
use serde::{Deserialize, Serialize};

/// Current redacted finding-envelope version.
pub const TRIAGE_ENVELOPE_VERSION: u32 = 1;
/// Current immediate runtime-suppression artifact version.
pub const TRIAGE_SUPPRESSION_VERSION: u32 = 1;
/// Current pattern-training feedback artifact version.
pub const PATTERN_FEEDBACK_VERSION: u32 = 1;
/// Maximum accepted records in one envelope.
pub const MAX_TRIAGE_RECORDS: usize = 4096;
/// Maximum serialized envelope size.
pub const MAX_TRIAGE_INPUT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum serialized size of either derived artifact.
pub const MAX_TRIAGE_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Redacted findings submitted for triage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriageEnvelope {
    /// Schema version. Only the current version is accepted.
    pub version: u32,
    /// Exact effective detector corpus identity emitted by the producing binary.
    pub detector_digest: String,
    /// Bounded redacted records.
    pub records: Vec<TriageRecord>,
}

/// One redacted triage decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriageRecord {
    /// BLAKE3 finding identity. Never the credential.
    pub finding_hash: String,
    /// Stable embedded detector identifier.
    pub detector_id: String,
    /// Exact public scanner provenance from `evidence.provenance`.
    pub provenance: FindingProvenance,
    /// BLAKE3 digest of bounded context. Never context bytes.
    pub context_digest: String,
    /// Human triage disposition.
    pub disposition: TriageDisposition,
    /// Typed reason carrying no free-form text.
    pub reason: TriageReason,
    /// Exactly one typed scope.
    pub scope: TriageScope,
}

/// Whether the finding was dismissed or confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TriageDisposition {
    /// Do not treat this occurrence as a secret.
    Dismissed,
    /// Treat this occurrence as a secret.
    Confirmed,
}

/// Closed reason vocabulary. Free-form text is deliberately not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TriageReason {
    /// Detector matched non-credential material.
    FalsePositive,
    /// Credential is an intentional test fixture.
    TestFixture,
    /// Credential is an approved public example.
    ApprovedExample,
    /// Finding duplicates another finding.
    Duplicate,
    /// Credential was revoked or rotated.
    RevokedOrRotated,
    /// Credential is confirmed active.
    ConfirmedActive,
    /// Credential is confirmed but activity is unknown.
    ConfirmedSecret,
}

/// Scope of one decision. The enum representation makes scopes mutually exclusive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TriageScope {
    /// Suppress only this finding identity.
    Exact,
    /// Suppress matching findings at one redacted path identity.
    Path {
        /// BLAKE3 path identity, never a filesystem path.
        path_hash: String,
    },
    /// Suppress matching findings in one redacted repository identity.
    Repository {
        /// BLAKE3 repository identity, never a repository path or URL.
        repository_hash: String,
    },
    /// Feed training only and never create runtime suppression.
    PatternFeedbackOnly,
}

/// Versioned immediate runtime-suppression artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSuppressions {
    /// Runtime-suppression schema version.
    pub suppression_version: u32,
    /// Exact detector corpus identity.
    pub detector_digest: String,
    /// Dismissed, runtime-applicable records only.
    pub suppressions: Vec<RuntimeSuppression>,
}

/// One immediate scoped suppression decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSuppression {
    /// Finding identity.
    pub finding_hash: String,
    /// Stable detector identifier.
    pub detector_id: String,
    /// Exact public scanner provenance.
    pub provenance: FindingProvenance,
    /// Bounded context digest.
    pub context_digest: String,
    /// Runtime scope. Pattern-feedback-only is unrepresentable here.
    pub scope: RuntimeSuppressionScope,
    /// Typed dismissal reason.
    pub reason: TriageReason,
}

/// Runtime-applicable suppression scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeSuppressionScope {
    /// One finding.
    Exact,
    /// One redacted path identity.
    Path {
        /// BLAKE3 path identity.
        path_hash: String,
    },
    /// One redacted repository identity.
    Repository {
        /// BLAKE3 repository identity.
        repository_hash: String,
    },
}

/// Versioned pattern-training feedback artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternFeedback {
    /// Pattern-feedback schema version.
    pub pattern_feedback_version: u32,
    /// Exact detector corpus identity.
    pub detector_digest: String,
    /// Validated redacted feedback records.
    pub feedback: Vec<PatternFeedbackRecord>,
}

/// One pattern-training observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternFeedbackRecord {
    /// Finding identity.
    pub finding_hash: String,
    /// Stable detector identifier.
    pub detector_id: String,
    /// Exact public scanner provenance.
    pub provenance: FindingProvenance,
    /// Bounded context digest.
    pub context_digest: String,
    /// Triage disposition.
    pub disposition: TriageDisposition,
    /// Typed reason.
    pub reason: TriageReason,
    /// Original typed scope, retained for training policy.
    pub scope: TriageScope,
}

impl TriageEnvelope {
    /// Parse and validate the current redacted contract for one active corpus.
    pub fn from_json(bytes: &[u8], expected_detector_digest: &str) -> Result<Self, String> {
        if bytes.len() > MAX_TRIAGE_INPUT_BYTES {
            return Err("triage envelope exceeds the byte limit".to_owned());
        }
        let envelope: Self = serde_json::from_slice(bytes).map_err(|_| {
            "triage envelope is malformed or contains unsupported fields".to_owned()
        })?;
        envelope.validate(expected_detector_digest)?;
        Ok(envelope)
    }

    /// Validate versions, bounds, identities, and reason/disposition coherence.
    pub fn validate(&self, expected_detector_digest: &str) -> Result<(), String> {
        if self.version != TRIAGE_ENVELOPE_VERSION {
            return Err("unsupported triage envelope version".to_owned());
        }
        let detector_digest =
            validate_active_detector_digest(&self.detector_digest, expected_detector_digest)?;
        if self.records.len() > MAX_TRIAGE_RECORDS {
            return Err("triage envelope exceeds the record limit".to_owned());
        }
        for record in &self.records {
            validate_record(record, detector_digest)?;
        }
        Ok(())
    }

    /// Derive distinct runtime-suppression and pattern-feedback artifacts.
    pub fn into_outputs(self) -> (RuntimeSuppressions, PatternFeedback) {
        let mut suppressions = Vec::with_capacity(self.records.len());
        let mut feedback = Vec::with_capacity(self.records.len());
        for record in self.records {
            if record.disposition == TriageDisposition::Dismissed {
                let runtime_scope = match &record.scope {
                    TriageScope::Exact => Some(RuntimeSuppressionScope::Exact),
                    TriageScope::Path { path_hash } => Some(RuntimeSuppressionScope::Path {
                        path_hash: path_hash.clone(),
                    }),
                    TriageScope::Repository { repository_hash } => {
                        Some(RuntimeSuppressionScope::Repository {
                            repository_hash: repository_hash.clone(),
                        })
                    }
                    TriageScope::PatternFeedbackOnly => None,
                };
                if let Some(scope) = runtime_scope {
                    suppressions.push(RuntimeSuppression {
                        finding_hash: record.finding_hash.clone(),
                        detector_id: record.detector_id.clone(),
                        provenance: record.provenance,
                        context_digest: record.context_digest.clone(),
                        scope,
                        reason: record.reason,
                    });
                }
            }
            feedback.push(PatternFeedbackRecord {
                finding_hash: record.finding_hash,
                detector_id: record.detector_id,
                provenance: record.provenance,
                context_digest: record.context_digest,
                disposition: record.disposition,
                reason: record.reason,
                scope: record.scope,
            });
        }
        (
            RuntimeSuppressions {
                suppression_version: TRIAGE_SUPPRESSION_VERSION,
                detector_digest: self.detector_digest.clone(),
                suppressions,
            },
            PatternFeedback {
                pattern_feedback_version: PATTERN_FEEDBACK_VERSION,
                detector_digest: self.detector_digest,
                feedback,
            },
        )
    }
}

impl RuntimeSuppressions {
    /// Parse only the runtime-suppression contract for one active corpus.
    pub fn from_json(bytes: &[u8], expected_detector_digest: &str) -> Result<Self, String> {
        if bytes.len() > MAX_TRIAGE_OUTPUT_BYTES {
            return Err("runtime suppression artifact exceeds the byte limit".to_owned());
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| "runtime suppression artifact is malformed".to_owned())?;
        if value.suppression_version != TRIAGE_SUPPRESSION_VERSION {
            return Err("unsupported runtime suppression version".to_owned());
        }
        let detector_digest =
            validate_active_detector_digest(&value.detector_digest, expected_detector_digest)?;
        if value.suppressions.len() > MAX_TRIAGE_RECORDS {
            return Err("runtime suppression artifact exceeds the record limit".to_owned());
        }
        for record in &value.suppressions {
            validate_digest(&record.finding_hash, "finding")?;
            validate_provenance(&record.detector_id, record.provenance, detector_digest)?;
            validate_digest(&record.context_digest, "context")?;
            if !matches!(
                record.reason,
                TriageReason::FalsePositive
                    | TriageReason::TestFixture
                    | TriageReason::ApprovedExample
                    | TriageReason::Duplicate
                    | TriageReason::RevokedOrRotated
            ) {
                return Err("runtime suppression contains a confirmation reason".to_owned());
            }
            match &record.scope {
                RuntimeSuppressionScope::Path { path_hash } => validate_digest(path_hash, "path")?,
                RuntimeSuppressionScope::Repository { repository_hash } => {
                    validate_digest(repository_hash, "repository")?
                }
                RuntimeSuppressionScope::Exact => {}
            }
        }
        Ok(value)
    }
}

impl PatternFeedback {
    /// Parse only the pattern-feedback contract for one active corpus.
    pub fn from_json(bytes: &[u8], expected_detector_digest: &str) -> Result<Self, String> {
        if bytes.len() > MAX_TRIAGE_OUTPUT_BYTES {
            return Err("pattern feedback artifact exceeds the byte limit".to_owned());
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| "pattern feedback artifact is malformed".to_owned())?;
        if value.pattern_feedback_version != PATTERN_FEEDBACK_VERSION {
            return Err("unsupported pattern feedback version".to_owned());
        }
        let detector_digest =
            validate_active_detector_digest(&value.detector_digest, expected_detector_digest)?;
        if value.feedback.len() > MAX_TRIAGE_RECORDS {
            return Err("pattern feedback artifact exceeds the record limit".to_owned());
        }
        for record in &value.feedback {
            validate_record_fields(TriageRecordFields::from(record), detector_digest)?;
        }
        Ok(value)
    }
}

struct TriageRecordFields<'a> {
    finding_hash: &'a str,
    detector_id: &'a str,
    provenance: FindingProvenance,
    context_digest: &'a str,
    disposition: TriageDisposition,
    reason: TriageReason,
    scope: &'a TriageScope,
}

impl<'a> From<&'a TriageRecord> for TriageRecordFields<'a> {
    fn from(record: &'a TriageRecord) -> Self {
        Self {
            finding_hash: &record.finding_hash,
            detector_id: &record.detector_id,
            provenance: record.provenance,
            context_digest: &record.context_digest,
            disposition: record.disposition,
            reason: record.reason,
            scope: &record.scope,
        }
    }
}

impl<'a> From<&'a PatternFeedbackRecord> for TriageRecordFields<'a> {
    fn from(record: &'a PatternFeedbackRecord) -> Self {
        Self {
            finding_hash: &record.finding_hash,
            detector_id: &record.detector_id,
            provenance: record.provenance,
            context_digest: &record.context_digest,
            disposition: record.disposition,
            reason: record.reason,
            scope: &record.scope,
        }
    }
}

fn validate_record(record: &TriageRecord, expected_detector_digest: u64) -> Result<(), String> {
    validate_record_fields(TriageRecordFields::from(record), expected_detector_digest)
}

fn validate_record_fields(
    record: TriageRecordFields<'_>,
    expected_detector_digest: u64,
) -> Result<(), String> {
    validate_digest(record.finding_hash, "finding")?;
    validate_digest(record.context_digest, "context")?;
    validate_provenance(
        record.detector_id,
        record.provenance,
        expected_detector_digest,
    )?;
    let coherent = matches!(
        (record.disposition, record.reason),
        (
            TriageDisposition::Dismissed,
            TriageReason::FalsePositive
                | TriageReason::TestFixture
                | TriageReason::ApprovedExample
                | TriageReason::Duplicate
                | TriageReason::RevokedOrRotated
        ) | (
            TriageDisposition::Confirmed,
            TriageReason::ConfirmedActive | TriageReason::ConfirmedSecret
        )
    );
    if !coherent {
        return Err("triage disposition and reason disagree".to_owned());
    }
    match record.scope {
        TriageScope::Path { path_hash } => validate_digest(path_hash, "path")?,
        TriageScope::Repository { repository_hash } => {
            validate_digest(repository_hash, "repository")?
        }
        TriageScope::Exact | TriageScope::PatternFeedbackOnly => {}
    }
    Ok(())
}

fn validate_provenance(
    detector_id: &str,
    provenance: FindingProvenance,
    expected_detector_digest: u64,
) -> Result<(), String> {
    let canonical_detector_id = canonical_report_detector_id(detector_id)?;
    if provenance.detector_digest() != Some(expected_detector_digest) {
        return Err("stale or unattributed finding provenance".to_owned());
    }
    if matches!(
        provenance.context_class(),
        crate::EvidenceReasonCode::Unattributed | crate::EvidenceReasonCode::LiveVerification
    ) {
        return Err("invalid scanner provenance context".to_owned());
    }
    match provenance.candidate_channel() {
        FindingCandidateChannel::Pattern => {
            let detector = crate::detector_spec_by_id(canonical_detector_id)
                .ok_or_else(|| "stale detector identifier".to_owned())?;
            let pattern_index = provenance
                .pattern_index()
                .ok_or_else(|| "missing pattern identity".to_owned())?;
            let current = usize::try_from(pattern_index)
                .ok()
                .is_some_and(|index| index < detector.patterns.len());
            if !current {
                return Err("stale pattern identity".to_owned());
            }
        }
        FindingCandidateChannel::GenericAssignment => {
            let detector = crate::detector_spec_by_id(canonical_detector_id)
                .ok_or_else(|| "stale detector identifier".to_owned())?;
            if detector.kind != crate::DetectorKind::Phase2Generic {
                return Err("detector does not own generic-assignment findings".to_owned());
            }
        }
        FindingCandidateChannel::Entropy => {
            let owns_entropy_id = crate::embedded_detector_specs().iter().any(|detector| {
                detector
                    .entropy_fallback
                    .as_ref()
                    .is_some_and(|fallback| fallback.id == canonical_detector_id)
            });
            if !owns_entropy_id {
                return Err("stale entropy detector identifier".to_owned());
            }
        }
        FindingCandidateChannel::Unattributed => {
            return Err("unattributed findings cannot produce triage feedback".to_owned());
        }
    }
    Ok(())
}

fn canonical_report_detector_id(detector_id: &str) -> Result<&str, String> {
    let canonical = detector_id
        .strip_suffix(crate::REASSEMBLED_DETECTOR_SUFFIX)
        .unwrap_or(detector_id);
    if canonical.is_empty()
        || canonical.len() > 128
        || canonical.contains(':')
        || !canonical
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("invalid detector identifier".to_owned());
    }
    Ok(canonical)
}

fn validate_active_detector_digest(actual: &str, expected: &str) -> Result<u64, String> {
    let actual = parse_detector_digest(actual)?;
    let expected = parse_detector_digest(expected)?;
    if actual != expected {
        return Err("stale detector corpus identity".to_owned());
    }
    Ok(expected)
}

fn validate_detector_digest(value: &str) -> Result<(), String> {
    if value.len() == 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("invalid detector corpus digest".to_owned())
    }
}

fn parse_detector_digest(value: &str) -> Result<u64, String> {
    validate_detector_digest(value)?;
    u64::from_str_radix(value, 16).map_err(|_| "invalid detector corpus digest".to_owned())
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    let valid = value.len() == 71
        && value.starts_with("blake3:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(format!("invalid {label} digest"))
    }
}
