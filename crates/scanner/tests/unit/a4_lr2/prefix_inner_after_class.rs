use keyhog_scanner::testing::extract_inner_literals;

#[test]
fn prefix_inner_after_class() {
    assert_eq!(
        extract_inner_literals(r"[a-zA-Z0-9]{20}_AKIA[A-Z0-9]{16}"),
        vec!["_AKIA"]
    );
}
