use keyhog_core::VerificationResult;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn exact_live_and_dead_lines_still_map() {
    assert!(matches!(
        TestApi.script_auth_result_for_test("STATUS: LIVE\n"),
        VerificationResult::Live
    ));
    assert!(matches!(
        TestApi.script_auth_result_for_test("prefix\nSTATUS: DEAD\n"),
        VerificationResult::Dead
    ));
}

#[test]
fn substring_live_without_status_line_is_error() {
    let result = TestApi.script_auth_result_for_test("NOTE: NOT STATUS: LIVE in this banner");
    assert!(
        matches!(result, VerificationResult::Error(_)),
        "substring mentions must not count as LIVE, got {result:?}"
    );
}

#[test]
fn mixed_live_and_dead_lines_are_ambiguous_error() {
    let result = TestApi.script_auth_result_for_test("STATUS: DEAD\nSTATUS: LIVE\n");
    match result {
        VerificationResult::Error(message) => assert!(
            message.contains("ambiguous"),
            "mixed statuses must fail closed: {message}"
        ),
        other => panic!("expected ambiguous Error, got {other:?}"),
    }
}
