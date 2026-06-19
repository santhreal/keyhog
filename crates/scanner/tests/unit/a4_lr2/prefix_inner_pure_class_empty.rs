use keyhog_scanner::testing::extract_inner_literals;

#[test]
fn prefix_inner_pure_class_empty() {
    assert!(extract_inner_literals(r"[a-f0-9]{32}").is_empty());
}
