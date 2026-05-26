//! Migrated from `src/lib.rs` — redacted output must not contain the full secret.

use keyhog_core::redact;

#[test]
fn redact_does_not_leak_full_secret_in_owned_output() {
    let secret = concat!("sk_li", "ve_abcdefghijklmnopqrstuvwxyz");
    let redacted = redact(secret);
    assert!(!redacted.contains(secret));
    assert!(redacted.contains("..."));
}
