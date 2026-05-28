#[test]
fn compiler_alt_none_literal() {
    assert!(keyhog_scanner::testing::rewrite_alternation_prefix("AKIA[A-Z0-9]{16}", "[a]kia").is_none());
}
