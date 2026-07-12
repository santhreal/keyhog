//! Gate: hot-pattern suppression must not fork the shared suppression owner.

use super::support::*;

#[test]
fn hot_pattern_suppression_routes_through_suppression_owner() {
    let src = scanner_src();
    let suppression = uncommented_code(&read(&src.join("suppression/api.rs")));
    assert!(
        !suppression.contains("struct HotPatternSuppressionCtx")
            && !suppression.contains("fn hot_pattern_suppression_stage("),
        "suppression::api must not keep a hot-pattern-only suppression fork"
    );
    assert!(
        !suppression.contains("fn suppress_hot_pattern_candidate("),
        "hot-pattern suppression must not regress to a silent bool API"
    );

    let hot_patterns = uncommented_code(&read(&src.join("engine/hot_patterns.rs")));
    assert!(
        hot_patterns.contains("self.process_match(")
            && hot_patterns.contains("crate::adjudicate::record_suppression(")
            && hot_patterns.contains("crate::adjudicate::MatchCtx::for_hot_pattern(")
            && hot_patterns.contains("crate::adjudicate::HotPatternSignal::ShapeGate(")
            && hot_patterns.contains("\"hot_regex_validation_rejected\"")
            && !hot_patterns.contains("credential.len() < min_len"),
        "hot-pattern fast path may record validator drops, then must delegate real findings to process_match"
    );
    assert!(
        !hot_patterns.contains("crate::adjudicate::record_stage_suppression(")
            && !hot_patterns.contains("crate::adjudicate::StageId::ChecksumInvalid")
            && !hot_patterns.contains("crate::adjudicate::StageId::ShapeGate("),
        "hot-pattern fast path must not name adjudicator StageIds directly"
    );
    for forbidden in [
        "hot_pattern_suppression_stage",
        "HotPatternSuppressionCtx",
        "suppress_known_example_credential",
        "looks_like_regex_literal_tail",
        "looks_like_vendored_minified_path",
        "looks_like_secret_scanner_source",
        "binary-strings",
        "archive-binary",
        "base64_string",
    ] {
        assert!(
            !hot_patterns.contains(forbidden),
            "hot-pattern fast path must not own suppression policy token {forbidden:?}"
        );
    }
}
