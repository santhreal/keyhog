use keyhog_scanner::compiler::extract_inner_literals;

#[test]
fn prefix_inner_short_dropped() {
    assert!(keyhog_scanner::compiler::extract_inner_literals(r"wx[a-f0-9]{16}").is_empty());
}
