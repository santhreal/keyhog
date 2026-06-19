use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::collections::HashMap;

#[test]
fn interactsh_empty_collapses_to_empty() {
    let out = TestApi.interpolate("https://{{interactsh}}/x", "credential", &HashMap::new());
    assert_eq!(out, "https:///x");
}
