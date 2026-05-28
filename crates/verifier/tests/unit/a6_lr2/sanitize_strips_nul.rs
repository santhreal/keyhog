#[test]
fn sanitize_strips_nul() {
    assert!(!keyhog_verifier::testing::sanitize_raw_value("a\0b").contains('\0'));
}
