use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::collections::HashMap;

#[test]
fn interpolate_oob_url_malformed_scheme() {
    // When the URL lacks a proper scheme (no `://`), sanitize_oob_value
    // processes the entire string as a host, and the result is safe.
    // This test ensures that a missing or malformed scheme does not bypass
    // the hostname sanitization.
    // Malformed: no `://` scheme, but carries the host plus structural
    // punctuation. Exercises the no-scheme branch of the url interpolation
    // (whole value runs through sanitize_oob_value) while still letting us
    // assert the valid host bytes survive and the structural chars are stripped.
    let minted_url = "host.example.com/x?y=1";
    let comps =
        TestApi.companions_with_oob(&HashMap::new(), "host.example.com", minted_url, "id123");

    let body = TestApi.interpolate("{\"url\":\"{{interactsh.url}}\"}", "cred", &comps);

    // The malformed URL (lacking ://) gets treated as a raw host string,
    // so all structural chars (/ ? =) are stripped by sanitize_oob_value.
    // The output must not contain the escaped structural punctuation.
    assert!(!body.contains('?'), "query char leaked: {body}");
    assert!(!body.contains('='), "equals leaked: {body}");

    // The valid host bytes survive
    assert!(
        body.contains("host.example.com"),
        "valid host dropped: {body}"
    );
}
