#[test]
fn compiler_alt_nested() {
    assert_eq!(
        keyhog_scanner::testing::rewrite_alternation_prefix(
            "(?:abc(?:\\d{2})|def)body",
            "abc",
            "[a]bc"
        )
        .as_deref(),
        Some("[a]bc(?:\\d{2})body")
    );
}
