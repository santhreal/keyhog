#[test]
fn compiler_split_no_flag() {
    assert_eq!(keyhog_scanner::testing::split_leading_inline_flag("body"), ("", "body"));
}
