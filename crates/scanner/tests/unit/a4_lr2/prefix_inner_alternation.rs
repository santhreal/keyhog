use keyhog_scanner::testing::extract_inner_literals;

#[test]
fn prefix_inner_alternation() {
    let lits = extract_inner_literals(r"(?:secret|api_key)\s*=\s*[a-z0-9]{32}");
    assert!(lits.iter().any(|s| s == "secret"));
    assert!(lits.iter().any(|s| s == "api_key"));
}

#[test]
fn prefix_inner_alternation_requires_every_branch_to_have_a_trigger() {
    assert!(extract_inner_literals(r"(?:DD.API.KEY|DATADOG.API.KEY)[=:]+[a-f0-9]{32}").is_empty());
}
