#[test]
fn compiler_alt_none_singleton() {
    assert!(keyhog_scanner::testing::rewrite_alternation_prefix("(?:foobody)tail", "[fF]oo").is_none());
}
