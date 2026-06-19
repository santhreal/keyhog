use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn sanitize_raw_value_other_ascii_controls() {
    // ASCII controls other than tab (0x00-0x08, 0x0A-0x1F) must be stripped.
    // Bell (0x07), Escape (0x1B), Unit Separator (0x1F), etc. can terminate
    // strings, truncate logs, or crash parsers.
    let input = "valid\u{0007}\u{0008}\u{000A}\u{001B}\u{001F}token";
    let result = TestApi.sanitize_raw_value(input);

    // All non-tab ASCII controls must be absent
    assert!(!result.contains('\u{0007}')); // BEL
    assert!(!result.contains('\u{0008}')); // BS
    assert!(!result.contains('\u{000A}')); // LF
    assert!(!result.contains('\u{001B}')); // ESC
    assert!(!result.contains('\u{001F}')); // US

    // Valid alphanumeric survives
    assert_eq!(result, "validtoken");
}
