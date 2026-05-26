use keyhog_verifier::interpolate::{companions_with_oob, interpolate};
use std::collections::HashMap;

#[test]
fn interactsh_id_substitutes_correlation_id() {
    let c = companions_with_oob(
        &HashMap::new(),
        "abc123def456ghi789jkl0mnopqrstuv1.oast.fun",
        "https://abc123def456ghi789jkl0mnopqrstuv1.oast.fun",
        "abc123def456ghi789jkl0mnopqrstuv1",
    );
    assert_eq!(
        interpolate("oob_id={{interactsh.id}}", "credential", &c),
        "oob_id=abc123def456ghi789jkl0mnopqrstuv1"
    );
}
