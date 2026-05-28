use keyhog_scanner::compiler::extract_inner_literals;

#[test]
fn prefix_inner_pure_class_empty() {
    assert!(keyhog_scanner::compiler::extract_inner_literals(r"[a-f0-9]{32}").is_empty());
}
