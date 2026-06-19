use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::collections::HashMap;

#[test]
fn resolve_field_match() {
    assert_eq!(
        TestApi.resolve_field("match", "cred123", &HashMap::new()),
        "cred123"
    );
}

#[test]
fn resolve_field_companion() {
    let mut companions = HashMap::new();
    companions.insert("secret".to_string(), "sec123".to_string());
    assert_eq!(
        TestApi.resolve_field("companion.secret", "key", &companions),
        "sec123"
    );
}

#[test]
fn resolve_field_literal() {
    assert_eq!(
        TestApi.resolve_field("Bearer", "cred", &HashMap::new()),
        "Bearer"
    );
}

#[test]
fn interpolate_match_in_url() {
    let result = TestApi.interpolate(
        "https://api.example.com/check?key={{match}}",
        "abc123",
        &HashMap::new(),
    );
    // Assert the exact substituted URL, not just substring containment.
    // The contains() assertion would still pass if the interpolator
    // produced `https://api.example.com/check?key={{match}}abc123` or
    // `abc123foo` - both shapes are broken HTTP requests that would
    // hit unexpected endpoints in production.
    assert_eq!(result, "https://api.example.com/check?key=abc123");
}

#[test]
fn interpolate_companion() {
    let mut companions = HashMap::new();
    companions.insert("secret".to_string(), "mysecret".to_string());
    let result = TestApi.interpolate("{{companion.secret}}", "key", &companions);
    assert_eq!(result, "mysecret");
}

#[test]
fn interpolate_strips_crlf_from_raw_match() {
    let result = TestApi.interpolate(
        "{{match}}",
        "value\r\nInjected-Header: evil",
        &HashMap::new(),
    );

    assert_eq!(result, "valueInjected-Header: evil");
    assert!(!result.contains('\r'));
    assert!(!result.contains('\n'));
}
