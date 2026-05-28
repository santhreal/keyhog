#[test]
fn compiler_alt_nested() {
    assert_eq!(keyhog_scanner::testing::rewrite_alternation_prefix("(?:abc(?:\\d{2})|def)body", "[a]bc").as_deref(), Some("[a]bcbody"));
}
