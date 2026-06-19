use keyhog_scanner::testing::is_within_hex_context;

#[test]
fn prose_match_not_in_hex_context() {
    let data = "this is not a hex secret value";
    assert!(!is_within_hex_context(data, 8, 14));
}
