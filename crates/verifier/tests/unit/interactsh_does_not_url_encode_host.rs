use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::collections::HashMap;

#[test]
fn interactsh_does_not_url_encode_host() {
    let c = TestApi.companions_with_oob(
        &HashMap::new(),
        "abc123def456ghi789jkl0mnopqrstuv1.oast.fun",
        "https://abc123def456ghi789jkl0mnopqrstuv1.oast.fun",
        "abc123def456ghi789jkl0mnopqrstuv1",
    );
    let out = TestApi.interpolate("host={{interactsh}}", "x", &c);
    assert!(out.contains("oast.fun"));
    assert!(!out.contains("%2E"));
}
