//! Migrated from `src/lib.rs` - empty credential redacts to four stars.

use keyhog_core::redact;

#[test]
fn redact_empty_string_returns_stars() {
    assert_eq!(redact(""), "****");
}
