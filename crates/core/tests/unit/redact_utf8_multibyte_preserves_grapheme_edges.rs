//! UTF-8 credentials use char boundaries, not byte slices, when redacting.

use keyhog_core::redact;

#[test]
fn redact_utf8_multibyte_preserves_grapheme_edges() {
    let secret = "🔑🔑🔑🔑🔑🔑🔑🔑🔑";
    let redacted = redact(secret);
    assert_eq!(redacted, "🔑...🔑");
    assert!(!redacted.contains(secret));
}
