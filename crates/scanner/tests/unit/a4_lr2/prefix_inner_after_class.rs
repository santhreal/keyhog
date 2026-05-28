use keyhog_scanner::compiler::extract_inner_literals;

#[test]
fn prefix_inner_after_class() {
    assert_eq!(keyhog_scanner::compiler::extract_inner_literals(r"[a-zA-Z0-9]{20}_AKIA[A-Z0-9]{16}"), vec!["_AKIA"]);
}
