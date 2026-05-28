use keyhog_scanner::compiler::extract_inner_literals;

#[test]
fn prefix_inner_alternation() {
    let lits = keyhog_scanner::compiler::extract_inner_literals(r"(?:secret|api_key)\s*=\s*[a-z0-9]{32}");
    assert!(lits.iter().any(|s| s == "secret"));
    assert!(lits.iter().any(|s| s == "api_key"));
}
