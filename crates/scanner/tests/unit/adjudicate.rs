use crate::adjudicate::{
    adjudicate_match, CandidateMatch, MatchCtx, ProcessCandidateSignals, StageId, Verdict,
};
use crate::context::CodeContext;
use crate::suppression::NamedDetectorSuppressionCtx;

fn adjudicate_process_signal(
    detector_id: &str,
    credential: &str,
    data: &str,
    start: usize,
    end: usize,
) -> Verdict {
    let signals = ProcessCandidateSignals::from_match(detector_id, credential, data, start, end);
    adjudicate_match(
        CandidateMatch::new(credential),
        &MatchCtx::for_process_signals(signals),
    )
}

#[test]
fn process_stage_preserves_aws_length_before_hex_context_order() {
    let data = "feedfacefeedfacefeedfacefeedface";
    let credential = &data[8..24];

    assert_eq!(
        adjudicate_process_signal(crate::detector_ids::AWS_ACCESS_KEY, credential, data, 8, 24),
        Verdict::Suppressed(StageId::AwsAccessKeyLengthInvalid)
    );
}

#[test]
fn process_stage_suppresses_anthropic_legacy_length() {
    let credential = "sk-ant-api03-short";

    assert_eq!(
        adjudicate_process_signal(
            crate::detector_ids::ANTHROPIC_API_KEY,
            credential,
            credential,
            0,
            credential.len()
        ),
        Verdict::Suppressed(StageId::AnthropicLegacyLengthInvalid)
    );
}

#[test]
fn process_stage_suppresses_hex_digest_fragment() {
    let data = "sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let start = data.find("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let credential = &data[start..start + 32];

    assert_eq!(
        adjudicate_process_signal("algolia-admin-api-key", credential, data, start, start + 32),
        Verdict::Suppressed(StageId::HexDigestFragment)
    );
}

#[test]
fn process_stage_suppresses_generic_without_prefix_not_promising() {
    let credential = "aaaaaaaaaaaaaaaaaaaaaaaa";

    assert_eq!(
        adjudicate_process_signal(
            crate::detector_ids::GENERIC_SECRET,
            credential,
            credential,
            0,
            credential.len()
        ),
        Verdict::Suppressed(StageId::ProbabilisticGateNotPromising)
    );
}

#[test]
fn process_stage_suppresses_false_positive_context() {
    let credential = "AKIAIOSFODNN7EXAMPLE";
    let ctx =
        MatchCtx::for_process_signals(ProcessCandidateSignals::from_false_positive_context(true));

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::FalsePositiveContext)
    );
}

#[test]
fn process_stage_suppresses_missing_required_companion() {
    let credential = "AKIAIOSFODNN7EXAMPLE";
    let ctx = MatchCtx::for_process_signals(
        ProcessCandidateSignals::from_missing_required_companion(true),
    );

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::MissingRequiredCompanion)
    );
}

#[test]
fn process_stage_preserves_entropy_floor_before_camel_order() {
    let credential = "getParameter";
    let ctx =
        MatchCtx::for_process_signals(ProcessCandidateSignals::from_entropy_shape(true, true));

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::EntropyBelowFloor)
    );
}

#[test]
fn process_stage_suppresses_camel_case_no_digit() {
    let credential = "getParameter";
    let ctx =
        MatchCtx::for_process_signals(ProcessCandidateSignals::from_entropy_shape(false, true));

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::CamelCaseNoDigit)
    );
}

#[test]
fn process_stage_suppresses_checksum_invalid() {
    let credential = "ghp_invalidchecksum000000000000000000000";
    let ctx = MatchCtx::for_process_signals(ProcessCandidateSignals::from_checksum_invalid(true));

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::ChecksumInvalid)
    );
}

#[test]
fn process_stage_suppresses_scoring_rejected() {
    let credential = "AKIAIOSFODNN7EXAMPLE";
    let ctx = MatchCtx::for_process_signals(ProcessCandidateSignals::from_scoring_rejected(true));

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::ScoringRejected)
    );
}

#[test]
fn process_stage_suppresses_report_confidence_rejected() {
    let credential = "AKIAIOSFODNN7EXAMPLE";
    let ctx = MatchCtx::for_process_signals(
        ProcessCandidateSignals::from_report_confidence_rejected(true),
    );

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::ReportConfidenceRejected)
    );
}

#[test]
fn process_stage_reports_service_anchored_candidate() {
    let credential = "AKIAIOSFODNN7EXAMPLE";

    assert_eq!(
        adjudicate_process_signal(
            crate::detector_ids::AWS_ACCESS_KEY,
            credential,
            credential,
            0,
            credential.len()
        ),
        Verdict::Reported
    );
}

#[test]
fn explicit_stage_reports_generic_named_detector_owned_keyword() {
    let credential = "segment_write_key";
    let ctx = MatchCtx::for_stage(StageId::GenericNamedDetectorOwnedKeyword);

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::GenericNamedDetectorOwnedKeyword)
    );
    assert_eq!(
        StageId::GenericNamedDetectorOwnedKeyword.as_str(),
        "generic_named_detector_owned_keyword"
    );
}

#[test]
fn explicit_stage_reports_bare_auth_unstructured() {
    let credential = "not-a-structured-authorization-value";
    let ctx = MatchCtx::for_stage(StageId::BareAuthUnstructured);

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::BareAuthUnstructured)
    );
    assert_eq!(
        StageId::BareAuthUnstructured.as_str(),
        "bare_auth_unstructured"
    );
}

#[test]
fn explicit_stage_reports_generic_value_shape_reason() {
    let credential = "DUMMY_TOKEN_VALUE_abc123def456";
    let ctx = MatchCtx::for_stage(StageId::GenericValueShape("known_example_or_placeholder"));

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::GenericValueShape("known_example_or_placeholder"))
    );
    assert_eq!(
        StageId::GenericValueShape("known_example_or_placeholder").as_str(),
        "known_example_or_placeholder"
    );
}

#[test]
fn explicit_stage_reports_generic_below_min_confidence() {
    let credential = "low-confidence-but-shaped-value";
    let ctx = MatchCtx::for_stage(StageId::GenericBelowMinConfidence);

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::GenericBelowMinConfidence)
    );
    assert_eq!(
        StageId::GenericBelowMinConfidence.as_str(),
        "generic_below_min_confidence"
    );
}

#[test]
fn named_detector_stage_suppresses_generic_identifier() {
    let ctx = MatchCtx::for_named_detector(NamedDetectorSuppressionCtx::with_weak_anchor(
        Some("webgoat/WebgoatContext.java"),
        CodeContext::Unknown,
        None,
        "generic-secret",
        false,
    ));

    assert_eq!(
        adjudicate_match(CandidateMatch::new("getParameter"), &ctx),
        Verdict::Suppressed(StageId::NamedDetectorSuppression)
    );
    assert_eq!(
        StageId::NamedDetectorSuppression.as_str(),
        "named_detector_suppressed"
    );
}

#[test]
fn named_detector_stage_reports_service_anchored_identifier() {
    let ctx = MatchCtx::for_named_detector(NamedDetectorSuppressionCtx::with_weak_anchor(
        Some("service/config.rs"),
        CodeContext::Unknown,
        None,
        "aws-secret-access-key",
        false,
    ));

    assert_eq!(
        adjudicate_match(CandidateMatch::new("getParameter"), &ctx),
        Verdict::Reported
    );
}
