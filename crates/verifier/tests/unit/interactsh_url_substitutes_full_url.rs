use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::collections::HashMap;

#[test]
fn interactsh_url_substitutes_full_url() {
    let c = TestApi.companions_with_oob(
        &HashMap::new(),
        "abc123def456ghi789jkl0mnopqrstuv1.oast.fun",
        "https://abc123def456ghi789jkl0mnopqrstuv1.oast.fun",
        "abc123def456ghi789jkl0mnopqrstuv1",
    );
    let out = TestApi.interpolate("{\"callback\":\"{{interactsh.url}}\"}", "credential", &c);
    assert!(out.contains("https://abc123def456ghi789jkl0mnopqrstuv1.oast.fun"));
    assert!(!out.contains("{{interactsh"));
}
