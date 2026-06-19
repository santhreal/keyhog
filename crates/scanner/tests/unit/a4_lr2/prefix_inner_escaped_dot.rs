use keyhog_scanner::testing::extract_inner_literals;

#[test]
fn prefix_inner_escaped_dot() {
    let lits = extract_inner_literals(r"https?://[^/]+\.lambda-url\.[a-z]+\.on\.aws/path");
    assert!(lits.iter().any(|s| s.contains("lambda-url")), "{lits:?}");
}
