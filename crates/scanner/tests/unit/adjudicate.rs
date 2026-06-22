use crate::adjudicate::{adjudicate_match, CandidateMatch, MatchCtx, StageId, Verdict};
use crate::context::CodeContext;
use crate::suppression::NamedDetectorSuppressionCtx;

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
