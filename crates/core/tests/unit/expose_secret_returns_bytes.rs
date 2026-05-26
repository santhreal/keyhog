//! Migrated from `src/credential.rs` inline tests.
use keyhog_core::Credential;
#[test]
fn expose_secret_returns_bytes() {
    let c = Credential::from_text("hello");
    assert_eq!(c.expose_secret(), b"hello");
    assert_eq!(c.expose_str(), Some("hello"));
}
