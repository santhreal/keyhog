use keyhog_verifier::interpolate::interpolate;
use std::collections::HashMap;

#[test]
fn interactsh_empty_collapses_to_empty() {
    let out = interpolate("https://{{interactsh}}/x", "credential", &HashMap::new());
    assert_eq!(out, "https:///x");
}
