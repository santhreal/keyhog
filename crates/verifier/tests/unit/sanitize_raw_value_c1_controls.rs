use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn sanitize_raw_value_c1_controls() {
    // C1 control bytes (0x80–0x9F) must be stripped. These can crash
    // downstream HTTP parsers or truncate log lines.
    let input = "valid\u{0080}\u{0081}\u{008F}\u{009F}token";
    let result = TestApi.sanitize_raw_value(input);

    // All C1 bytes must be absent from output
    assert!(!result.contains('\u{0080}'));
    assert!(!result.contains('\u{0081}'));
    assert!(!result.contains('\u{008F}'));
    assert!(!result.contains('\u{009F}'));

    // Valid alphanumeric survives
    assert!(result.contains("validtoken"));
    assert_eq!(result, "validtoken");
}
