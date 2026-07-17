use keyhog_scanner::testing::extract_inner_literals;

#[test]
fn prefixless_inner_literal_routes_are_declared_in_detector_toml() {
    let mut undeclared = Vec::new();
    for d in
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus must load")
    {
        for (pattern_index, p) in d.patterns.iter().enumerate() {
            if !keyhog_scanner::testing::extract_literal_prefixes(&p.regex).is_empty() {
                continue;
            }
            if p.required_literals.is_empty() && !extract_inner_literals(&p.regex).is_empty() {
                undeclared.push(format!("{}[{pattern_index}]", d.id));
            }
        }
    }
    assert!(
        undeclared.is_empty(),
        "prefixless patterns with safe literal routes must declare required_literals in their detector TOML: {undeclared:?}"
    );
}
