//! Migrated from `src/credential.rs` inline tests.
use keyhog_core::Credential;
#[test]
fn debug_redacts_bytes() {
    let c = Credential::from(concat!("AK", "IAIOSFODNN7EXAMPLE"));
    let s = format!("{c:?}");
    assert!(s.contains("redacted"));
    assert!(!s.contains("AKIA"));
}
