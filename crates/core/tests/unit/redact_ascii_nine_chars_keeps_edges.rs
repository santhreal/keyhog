//! Migrated from `src/lib.rs` — ASCII redaction keeps first/last four chars.

use keyhog_core::redact;

#[test]
fn redact_ascii_nine_chars_keeps_edges() {
    assert_eq!(redact("123456789"), "1234...6789");
}
