//! Credentials ending in EXAMPLE are known examples.

use keyhog_scanner::context::is_known_example_credential;

#[test]
fn context_example_credential_example_suffix() {
    assert!(
        is_known_example_credential("AKIAIOSFODNN7EXAMPLE"),
        "AWS documentation EXAMPLE suffix must suppress"
    );
    assert!(
        !is_known_example_credential("AKIAIOSFODNN7REALKEY"),
        "real-looking AKIA body must not auto-suppress"
    );
}
