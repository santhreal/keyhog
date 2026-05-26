//! Adversarial: ASCII secrets ≤8 chars redact to four stars only.

use keyhog_core::redact;

#[test]
fn redact_short_ascii_fully_masked() {
    assert_eq!(redact("short"), "****");
    assert_eq!(redact("12345678"), "****");
}
