use keyhog_core::triage::{
    PatternFeedback, RuntimeSuppression, RuntimeSuppressions, TriageDisposition, TriageEnvelope,
    TriageReason, TriageRecord, TriageScope, MAX_TRIAGE_INPUT_BYTES, MAX_TRIAGE_RECORDS,
    TRIAGE_ENVELOPE_VERSION,
};
use keyhog_core::FindingProvenance;

const DETECTOR_DIGEST: &str = "0123456789abcdef";

fn digest(byte: char) -> String {
    format!("blake3:{}", byte.to_string().repeat(64))
}

fn detector_id() -> &'static str {
    keyhog_core::embedded_detector_specs()
        .iter()
        .find(|detector| {
            detector.kind == keyhog_core::DetectorKind::Regex && !detector.patterns.is_empty()
        })
        .expect("embedded corpus has a regex detector")
        .id
        .as_str()
}

fn generic_detector_id() -> &'static str {
    keyhog_core::embedded_detector_specs()
        .iter()
        .find(|detector| detector.kind == keyhog_core::DetectorKind::Phase2Generic)
        .expect("embedded corpus has a generic-assignment owner")
        .id
        .as_str()
}

fn entropy_detector_id() -> &'static str {
    keyhog_core::embedded_detector_specs()
        .iter()
        .find_map(|detector| detector.entropy_fallback.as_ref())
        .expect("embedded corpus has an entropy owner")
        .id
        .as_str()
}

fn provenance(pattern_index: u32) -> FindingProvenance {
    FindingProvenance::pattern(
        u64::from_str_radix(DETECTOR_DIGEST, 16).expect("test detector digest"),
        pattern_index,
        keyhog_core::SemanticSourceRole::StandaloneToken,
        keyhog_core::EvidenceReasonCode::UnsupportedContext,
    )
}

fn envelope(scope: TriageScope) -> TriageEnvelope {
    TriageEnvelope {
        version: TRIAGE_ENVELOPE_VERSION,
        detector_digest: DETECTOR_DIGEST.to_owned(),
        records: vec![TriageRecord {
            finding_hash: digest('1'),
            detector_id: detector_id().to_owned(),
            provenance: provenance(0),
            context_digest: digest('2'),
            disposition: TriageDisposition::Dismissed,
            reason: TriageReason::FalsePositive,
            scope,
        }],
    }
}

#[test]
fn current_contract_round_trips_into_distinct_artifacts() {
    let input = serde_json::to_vec(&envelope(TriageScope::Exact)).expect("serialize input");
    let parsed =
        TriageEnvelope::from_json(&input, DETECTOR_DIGEST).expect("parse current envelope");
    let (runtime, feedback) = parsed.into_outputs();
    let runtime_bytes = serde_json::to_vec(&runtime).expect("serialize runtime");
    let feedback_bytes = serde_json::to_vec(&feedback).expect("serialize feedback");

    assert_eq!(
        RuntimeSuppressions::from_json(&runtime_bytes, DETECTOR_DIGEST)
            .expect("runtime round trip"),
        runtime
    );
    assert_eq!(
        PatternFeedback::from_json(&feedback_bytes, DETECTOR_DIGEST)
            .expect("feedback round trip"),
        feedback
    );
    assert!(
        RuntimeSuppressions::from_json(&feedback_bytes, DETECTOR_DIGEST).is_err(),
        "pattern feedback must be unparseable as runtime suppression"
    );
    assert!(
        PatternFeedback::from_json(&runtime_bytes, DETECTOR_DIGEST).is_err(),
        "runtime suppression must be unparseable as pattern feedback"
    );
}

#[test]
fn unknown_secret_fields_and_missing_provenance_are_rejected() {
    let base = serde_json::to_value(envelope(TriageScope::Exact)).expect("serialize envelope");
    let mut missing_all = base.clone();
    missing_all["records"][0]
        .as_object_mut()
        .expect("record object")
        .remove("provenance");
    assert!(TriageEnvelope::from_json(
        &serde_json::to_vec(&missing_all).expect("serialize missing provenance"),
        DETECTOR_DIGEST,
    )
    .is_err());
    for field in [
        "schema_version",
        "detector_digest",
        "pattern_index",
        "candidate_channel",
        "source_role",
        "context_class",
    ] {
        let mut missing = base.clone();
        missing["records"][0]["provenance"]
            .as_object_mut()
            .expect("provenance object")
            .remove(field);
        let bytes = serde_json::to_vec(&missing).expect("serialize missing provenance field");
        assert!(
            TriageEnvelope::from_json(&bytes, DETECTOR_DIGEST).is_err(),
            "missing authoritative provenance field {field} was accepted"
        );
    }

    let mut unknown = base;
    unknown["records"][0]["credential"] =
        serde_json::Value::String("plaintext-secret".to_owned());
    let bytes = serde_json::to_vec(&unknown).expect("serialize mutation");
    assert!(TriageEnvelope::from_json(&bytes, DETECTOR_DIGEST).is_err());
}

#[test]
fn stale_versions_detector_and_pattern_fail_closed() {
    let mut stale_version = envelope(TriageScope::Exact);
    stale_version.version += 1;
    assert!(stale_version.validate(DETECTOR_DIGEST).is_err());

    let mut malformed_detector = envelope(TriageScope::Exact);
    malformed_detector.detector_digest = "old-corpus".to_owned();
    assert!(malformed_detector.validate(DETECTOR_DIGEST).is_err());

    let mut stale_detector = envelope(TriageScope::Exact);
    stale_detector.detector_digest = "fedcba9876543210".to_owned();
    assert!(stale_detector.validate(DETECTOR_DIGEST).is_err());

    let mut stale_pattern = envelope(TriageScope::Exact);
    stale_pattern.records[0].provenance = provenance(u32::MAX);
    assert!(stale_pattern.validate(DETECTOR_DIGEST).is_err());

    let (mut runtime, mut feedback) = envelope(TriageScope::Exact).into_outputs();
    runtime.suppression_version += 1;
    feedback.pattern_feedback_version += 1;
    assert!(RuntimeSuppressions::from_json(
        &serde_json::to_vec(&runtime).expect("serialize stale runtime"),
        DETECTOR_DIGEST,
    )
    .is_err());
    assert!(PatternFeedback::from_json(
        &serde_json::to_vec(&feedback).expect("serialize stale feedback"),
        DETECTOR_DIGEST,
    )
    .is_err());
}

#[test]
fn public_provenance_digest_channel_and_context_fail_closed() {
    let digest = u64::from_str_radix(DETECTOR_DIGEST, 16).expect("test detector digest");
    let mut generic = envelope(TriageScope::Exact);
    generic.records[0].detector_id = generic_detector_id().to_owned();
    generic.records[0].provenance = FindingProvenance::generic_assignment(
        digest,
        keyhog_core::SemanticSourceRole::StructuredAssignmentValue,
        keyhog_core::EvidenceReasonCode::GenericAssignment,
    );
    generic
        .validate(DETECTOR_DIGEST)
        .expect("attributed generic provenance");

    let mut entropy = envelope(TriageScope::Exact);
    entropy.records[0].detector_id = entropy_detector_id().to_owned();
    entropy.records[0].provenance = FindingProvenance::entropy(
        digest,
        keyhog_core::SemanticSourceRole::StandaloneToken,
        keyhog_core::EvidenceReasonCode::EntropyOnly,
    );
    entropy
        .validate(DETECTOR_DIGEST)
        .expect("attributed entropy provenance");

    let mut reassembled = envelope(TriageScope::Exact);
    reassembled.records[0].detector_id =
        format!("{}{}", detector_id(), keyhog_core::REASSEMBLED_DETECTOR_SUFFIX);
    reassembled
        .validate(DETECTOR_DIGEST)
        .expect("reassembled finding retains its canonical detector owner");

    let mut wrong_channel = envelope(TriageScope::Exact);
    wrong_channel.records[0].provenance = FindingProvenance::generic_assignment(
        digest,
        keyhog_core::SemanticSourceRole::StructuredAssignmentValue,
        keyhog_core::EvidenceReasonCode::GenericAssignment,
    );
    assert!(wrong_channel.validate(DETECTOR_DIGEST).is_err());

    let mut unsupported_suffix = envelope(TriageScope::Exact);
    unsupported_suffix.records[0].detector_id = format!("{}:other", detector_id());
    assert!(unsupported_suffix.validate(DETECTOR_DIGEST).is_err());

    let mut stale_digest = envelope(TriageScope::Exact);
    stale_digest.records[0].provenance = FindingProvenance::pattern(
        0xfedcba9876543210,
        0,
        keyhog_core::SemanticSourceRole::StandaloneToken,
        keyhog_core::EvidenceReasonCode::UnsupportedContext,
    );
    assert!(stale_digest.validate(DETECTOR_DIGEST).is_err());

    let mut unattributed = envelope(TriageScope::Exact);
    unattributed.records[0].provenance = FindingProvenance::unattributed();
    assert!(unattributed.validate(DETECTOR_DIGEST).is_err());

    let mut post_verification = envelope(TriageScope::Exact);
    post_verification.records[0].provenance = FindingProvenance::pattern(
        digest,
        0,
        keyhog_core::SemanticSourceRole::StandaloneToken,
        keyhog_core::EvidenceReasonCode::LiveVerification,
    );
    assert!(post_verification.validate(DETECTOR_DIGEST).is_err());
}

#[test]
fn malicious_strings_and_cross_scope_fields_are_rejected() {
    let mut malicious = envelope(TriageScope::Exact);
    malicious.records[0].detector_id = "../../credential\nvalue".to_owned();
    assert!(malicious.validate(DETECTOR_DIGEST).is_err());

    let mut value =
        serde_json::to_value(envelope(TriageScope::Exact)).expect("serialize envelope");
    value["records"][0]["scope"] = serde_json::json!({
        "path": { "path_hash": digest('3') },
        "repository": { "repository_hash": digest('4') }
    });
    let bytes = serde_json::to_vec(&value).expect("serialize mutation");
    assert!(TriageEnvelope::from_json(&bytes, DETECTOR_DIGEST).is_err());
}

#[test]
fn record_and_byte_bounds_are_enforced() {
    let mut oversized = envelope(TriageScope::Exact);
    oversized.records = vec![oversized.records[0].clone(); MAX_TRIAGE_RECORDS + 1];
    assert!(oversized.validate(DETECTOR_DIGEST).is_err());
    assert!(TriageEnvelope::from_json(
        &vec![b' '; MAX_TRIAGE_INPUT_BYTES + 1],
        DETECTOR_DIGEST,
    )
    .is_err());
}

#[test]
fn pattern_feedback_only_never_creates_runtime_suppression() {
    let parsed = envelope(TriageScope::PatternFeedbackOnly);
    let (runtime, feedback) = parsed.into_outputs();
    assert_eq!(runtime.suppressions, Vec::<RuntimeSuppression>::new());
    assert_eq!(feedback.feedback.len(), 1);
    assert_eq!(
        feedback.feedback[0].disposition,
        TriageDisposition::Dismissed
    );
}
