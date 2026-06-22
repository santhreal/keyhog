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
