use crate::adjudicate::{
    adjudicate_match, CandidateMatch, EntropyFallbackSignal, EntropyGenerationSignal,
    EntropyShapeStage, FinalEmitSignals, GenericBridgeSignal, GenericValueShapeStage,
    HotPatternSignal, MatchCtx, ProcessCandidateSignals, ReportAdjudicationPolicy, StageId,
    Verdict,
};
use crate::context::CodeContext;
use crate::suppression::NamedDetectorSuppressionCtx;

fn adjudicate_process_signal(
    detector_id: &str,
    credential_shape: Option<&crate::credential_shapes::CredentialShapeRule>,
    credential: &str,
    data: &str,
    start: usize,
    end: usize,
) -> Verdict {
    let signals = ProcessCandidateSignals::from_match(
        detector_id,
        keyhog_core::detector_spec_by_id(detector_id).and_then(|spec| spec.min_len),
        credential_shape,
        credential,
        data,
        start,
        end,
    );
    adjudicate_match(
        CandidateMatch::new(credential),
        &MatchCtx::for_process_signals(signals),
    )
}

fn adjudicate_final_emit(
    detector_id: &str,
    credential: &str,
    code_context: CodeContext,
    confidence: f64,
    min_confidence_floor: f64,
    penalize_test_paths: bool,
) -> Verdict {
    let ctx = MatchCtx::for_final_emit(FinalEmitSignals::new(
        detector_id,
        code_context,
        confidence,
        min_confidence_floor,
        penalize_test_paths,
    ));
    adjudicate_match(CandidateMatch::new(credential), &ctx)
}

#[test]
fn process_stage_preserves_aws_length_before_hex_context_order() {
    let data = "feedfacefeedfacefeedfacefeedface";
    let credential = &data[8..24];
    let shape = crate::credential_shapes::CredentialShapeRule::exact_length_for_test(20);

    assert_eq!(
        adjudicate_process_signal("aws-access-key", Some(&shape), credential, data, 8, 24),
        Verdict::Suppressed(StageId::DetectorCredentialShapeInvalid)
    );
}

#[test]
fn process_stage_suppresses_anthropic_legacy_length() {
    let credential = "sk-ant-api03-short";
    let shape = crate::credential_shapes::CredentialShapeRule::prefix_body_range_for_test(
        "sk-ant-api03-",
        80,
        120,
    );

    assert_eq!(
        adjudicate_process_signal(
            "shape-test-detector",
            Some(&shape),
            credential,
            credential,
            0,
            credential.len()
        ),
        Verdict::Suppressed(StageId::DetectorCredentialShapeInvalid)
    );
}

#[test]
fn process_stage_suppresses_hex_digest_fragment() {
    let data = "sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let start = data.find("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let credential = &data[start..start + 32];

    assert_eq!(
        adjudicate_process_signal(
            "algolia-admin-api-key",
            None,
            credential,
            data,
            start,
            start + 32
        ),
        Verdict::Suppressed(StageId::HexDigestFragment)
    );
}

#[test]
fn process_stage_suppresses_generic_without_prefix_not_promising() {
    let credential = "aaaaaaaaaaaaaaaaaaaaaaaa";

    assert_eq!(
        adjudicate_process_signal(
            crate::detector_ids::GENERIC_SECRET,
            None,
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
fn process_stage_reports_service_anchored_candidate() {
    let credential = "AKIAIOSFODNN7EXAMPLE";
    let shape = crate::credential_shapes::CredentialShapeRule::exact_length_for_test(20);

    assert_eq!(
        adjudicate_process_signal(
            "aws-access-key",
            Some(&shape),
            credential,
            credential,
            0,
            credential.len()
        ),
        Verdict::Reported(None)
    );
}

#[test]
fn generic_bridge_stage_reports_named_detector_owned_keyword() {
    let credential = "segment_write_key";
    let ctx = MatchCtx::for_generic_bridge(GenericBridgeSignal::NamedDetectorOwnedKeyword);

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
fn generic_bridge_stage_reports_keyword_boundary() {
    let ctx = MatchCtx::for_generic_bridge(GenericBridgeSignal::KeywordBoundary);

    assert_eq!(
        adjudicate_match(CandidateMatch::new("bypass"), &ctx),
        Verdict::Suppressed(StageId::GenericKeywordBoundary)
    );
    assert_eq!(
        StageId::GenericKeywordBoundary.as_str(),
        "generic_keyword_boundary"
    );
}

#[test]
fn generic_bridge_stage_reports_bare_auth_unstructured() {
    let credential = "not-a-structured-authorization-value";
    let ctx = MatchCtx::for_generic_bridge(GenericBridgeSignal::BareAuthUnstructured);

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
fn generic_bridge_stage_reports_value_shape_reason() {
    let credential = "DUMMY_TOKEN_VALUE_abc123def456";
    let stage = GenericValueShapeStage::SharedSuppression("known_example_or_placeholder");
    let ctx = MatchCtx::for_generic_bridge(GenericBridgeSignal::ValueShape(stage));

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::GenericValueShape(stage))
    );
    assert_eq!(
        StageId::GenericValueShape(stage).as_str(),
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
fn explicit_stage_reports_entropy_named_detector_owned_assignment() {
    let credential = "segment_write_key";
    let ctx = MatchCtx::for_entropy_fallback(EntropyFallbackSignal::NamedDetectorOwnedAssignment);

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::EntropyNamedDetectorOwnedAssignment)
    );
    assert_eq!(
        StageId::EntropyNamedDetectorOwnedAssignment.as_str(),
        "entropy_named_detector_owned_assignment"
    );
}

#[test]
fn explicit_stage_reports_entropy_value_shape_reason() {
    let credential = "Yml0Y29pbgABAgMEBQYHCAkKCwwND/7+/f38+/r5+Pf=";
    let shape_stage = EntropyShapeStage::RandomBase64Blob;
    let ctx = MatchCtx::for_entropy_fallback(EntropyFallbackSignal::ValueShape(shape_stage));

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::EntropyValueShape(shape_stage))
    );
    assert_eq!(
        StageId::EntropyValueShape(shape_stage).as_str(),
        "entropy_random_base64_blob"
    );
}

#[test]
fn entropy_generation_stage_reports_plausibility_drop() {
    let credential = "structured.not.secret";
    let stage = StageId::EntropyValueShape(EntropyShapeStage::StructuredDottedTooShort);
    let ctx = MatchCtx::for_entropy_generation(EntropyGenerationSignal::SuppressionStage(stage));

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(stage)
    );
}

#[test]
fn explicit_stage_reports_hard_suppressed_context() {
    let credential = "documentation-only-token";
    let ctx = MatchCtx::for_stage(StageId::HardSuppressedContext);

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::HardSuppressedContext)
    );
    assert_eq!(
        StageId::HardSuppressedContext.as_str(),
        "hard_suppressed_context"
    );
}

#[test]
fn explicit_stage_reports_shape_gate_reason() {
    let credential = "PLACEHOLDER_TOKEN";
    let ctx = MatchCtx::for_stage(StageId::ShapeGate("placeholder_word"));

    assert_eq!(
        adjudicate_match(CandidateMatch::new(credential), &ctx),
        Verdict::Suppressed(StageId::ShapeGate("placeholder_word"))
    );
    assert_eq!(
        StageId::ShapeGate("placeholder_word").as_str(),
        "placeholder_word"
    );
}

#[test]
fn final_emit_stage_prefers_hard_context_before_floor() {
    assert_eq!(
        adjudicate_final_emit(
            "aws-access-key",
            "AKIAIOSFODNN7EXAMPLE",
            CodeContext::Documentation,
            0.40,
            0.85,
            true,
        ),
        Verdict::Suppressed(StageId::HardSuppressedContext)
    );
}

#[test]
fn final_emit_stage_names_generic_floor_drop() {
    assert_eq!(
        adjudicate_final_emit(
            crate::detector_ids::GENERIC_SECRET,
            "random_api_key_value_123456",
            CodeContext::Assignment,
            0.35,
            0.40,
            true,
        ),
        Verdict::Suppressed(StageId::GenericBelowMinConfidence)
    );
}

#[test]
fn final_emit_stage_preserves_known_prefix_not_promising_root_cause() {
    assert_eq!(
        adjudicate_final_emit(
            crate::detector_ids::GENERIC_API_KEY,
            "hf_ababababababababababababababababab",
            CodeContext::Assignment,
            0.80,
            0.85,
            true,
        ),
        Verdict::Suppressed(StageId::ProbabilisticGateNotPromising)
    );
}

#[test]
fn final_emit_stage_reports_final_confidence() {
    assert_eq!(
        adjudicate_final_emit(
            "datadog-api-key",
            "dd_api_key_12345678901234567890123456789012",
            CodeContext::Assignment,
            0.91,
            0.40,
            true,
        ),
        Verdict::Reported(Some(0.91))
    );
}

#[test]
fn final_report_candidate_returns_adjudicator_reported_confidence() {
    assert_eq!(
        crate::adjudicate::finalize_report_candidate(
            Some("service/config.rs"),
            "dd_api_key_12345678901234567890123456789012",
            ReportAdjudicationPolicy {
                detector_id: "datadog-api-key",
                code_context: CodeContext::Assignment,
                confidence: 0.91,
                min_confidence_floor: 0.40,
                penalize_test_paths: true,
                file_path: Some("service/config.rs"),
                is_named_detector: true,
                allow_encoded_text_lift: false,
                allow_canonical_hex_key: false,
                calibration: None,
            },
        ),
        Some(0.91)
    );
}

#[test]
fn hot_pattern_signal_reports_regex_validation() {
    assert_eq!(
        adjudicate_match(
            CandidateMatch::new("xoxb-bad-tail"),
            &MatchCtx::for_hot_pattern(HotPatternSignal::ShapeGate(
                "hot_regex_validation_rejected"
            )),
        ),
        Verdict::Suppressed(StageId::ShapeGate("hot_regex_validation_rejected"))
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
        false,
    ));

    assert_eq!(
        adjudicate_match(CandidateMatch::new("getParameter"), &ctx),
        Verdict::Suppressed(StageId::ShapeGate("pure_identifier_no_digit"))
    );
    assert_eq!(
        StageId::ShapeGate("pure_identifier_no_digit").as_str(),
        "pure_identifier_no_digit"
    );
}

#[test]
fn named_detector_stage_reports_exact_email_shape_reason() {
    let ctx = MatchCtx::for_named_detector(NamedDetectorSuppressionCtx::with_weak_anchor(
        Some("config.ini"),
        CodeContext::Unknown,
        None,
        crate::detector_ids::GENERIC_SECRET,
        false,
        false,
    ));

    assert_eq!(
        adjudicate_match(CandidateMatch::new("noreply@example.test"), &ctx),
        Verdict::Suppressed(StageId::ShapeGate("email_address"))
    );
}

#[test]
fn named_detector_stage_reports_shared_suppression_reason() {
    let ctx = MatchCtx::for_named_detector(NamedDetectorSuppressionCtx::with_weak_anchor(
        Some("service/config.rs"),
        CodeContext::Unknown,
        Some("filesystem"),
        "datadog-api-key",
        true,
        false,
    ));

    assert_eq!(
        adjudicate_match(
            CandidateMatch::new(
                "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            ),
            &ctx
        ),
        Verdict::Suppressed(StageId::ShapeGate("labelled_hash_digest"))
    );
}

#[test]
fn named_detector_stage_reports_decoded_inner_reason() {
    let ctx = MatchCtx::for_named_detector(NamedDetectorSuppressionCtx::with_weak_anchor(
        Some("secret.yaml"),
        CodeContext::Unknown,
        Some("filesystem"),
        "datadog-api-key",
        true,
        false,
    ));

    assert_eq!(
        adjudicate_match(
            CandidateMatch::new("YXJuOmF3czppYW06OjEyMzQ6cm9sZS9Y"),
            &ctx
        ),
        Verdict::Suppressed(StageId::ShapeGate("aws_iam_arn"))
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
        false,
    ));

    assert_eq!(
        adjudicate_match(CandidateMatch::new("getParameter"), &ctx),
        Verdict::Reported(None)
    );
}
