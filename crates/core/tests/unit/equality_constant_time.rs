//! Migrated from `src/credential.rs` inline tests.
use keyhog_core::Credential;
#[test]
fn equality_constant_time() {
    let a = Credential::from("aaa");
    let b = Credential::from("aaa");
    let c = Credential::from("aab");
    assert_eq!(a, b);
    assert_ne!(a, c);
}
