#[test]
fn compiler_split_flag_i() {
    assert_eq!(
        keyhog_scanner::testing::split_leading_inline_flag("(?i)body"),
        ("(?i)", "body")
    );
}
