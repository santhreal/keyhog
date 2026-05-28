#[test]
fn sanitize_strips_crlf() {
    assert!(!keyhog_verifier::testing::sanitize_raw_value("tok\r\nINJECT").contains('\n'));
}
