use keyhog_verifier::interpolate::{companions_with_oob, interpolate};
use std::collections::HashMap;

#[test]
fn interactsh_bare_substitutes_host() {
    let c = companions_with_oob(
        &HashMap::new(),
        "abc123def456ghi789jkl0mnopqrstuv1.oast.fun",
        "https://abc123def456ghi789jkl0mnopqrstuv1.oast.fun",
        "abc123def456ghi789jkl0mnopqrstuv1",
    );
    assert_eq!(
        interpolate("https://{{interactsh}}/x", "credential", &c),
        "https://abc123def456ghi789jkl0mnopqrstuv1.oast.fun/x"
    );
}
