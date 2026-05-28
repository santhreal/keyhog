#[test]
fn sanitize_keeps_tab() {
    assert_eq!(keyhog_verifier::testing::sanitize_raw_value("a\tb"), "a\tb");
}
