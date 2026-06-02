#[test]
fn sanitize_raw_value_del_byte() {
    // DEL byte (0x7F) must be stripped. It is a control character that can
    // crash or corrupt unhinged downstream parsers.
    let input = "token\u{007F}value";
    let result = keyhog_verifier::testing::sanitize_raw_value(input);

    // DEL byte must be absent
    assert!(!result.contains('\u{007F}'));

    // Valid bytes survive, DEL is simply removed
    assert_eq!(result, "tokenvalue");
}
