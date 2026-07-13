//! Gap test: the leading-assignment-key extractor's exact key slice + bounds.
//!
//! `generic_keyword_owner::leading_assignment_key` pulls the key out of a
//! `key=value` / `key:value` / `key~value` candidate prefix so that
//! `candidate_embeds_owned_assignment_key` can ask whether a named detector
//! owns that key (e.g. is `api_key=…` owned by a generic-keyword detector). It
//! scans leading "key bytes" (ASCII alphanumeric plus `_`, `-`, `.`) and then
//! requires the very next byte to be one of `=`, `:`, `~`; otherwise, and when
//! the whole string is key bytes (no terminator) or the first byte is already a
//! non-key byte (it yields `None`).
//!
//! The helper is live (the only caller is the assignment-owner fast path) but
//! had zero direct coverage. Pin the exact key slice it returns and every
//! `None` boundary. All vectors were traced against the exact byte logic.

use keyhog_scanner::testing::leading_assignment_key_for_test as key;

#[test]
fn extracts_the_key_for_every_accepted_terminator() {
    // Each accepted terminator: `=`, `:`, `~`.
    assert_eq!(key("api_key=secret").as_deref(), Some("api_key"));
    assert_eq!(key("api-key:val").as_deref(), Some("api-key"));
    assert_eq!(key("db.host~x").as_deref(), Some("db.host"));
    // A single-char key is fine.
    assert_eq!(key("a=b").as_deref(), Some("a"));
    // Every key-byte class (digit, `.`, `-`, `_`) is accepted in the key.
    assert_eq!(key("123.4-_=z").as_deref(), Some("123.4-_"));
    // A trailing `.` is itself a key byte, so it stays in the slice.
    assert_eq!(key("key.=v").as_deref(), Some("key."));
}

#[test]
fn a_terminator_with_no_value_still_yields_the_key() {
    // `end` stops at the `=` (index 3), which is not the string end (index 4),
    // so the empty value does not collapse to `None`.
    assert_eq!(key("key=").as_deref(), Some("key"));
}

#[test]
fn no_terminator_and_bad_terminators_yield_none() {
    assert_eq!(key("key"), None); // all key bytes, no terminator
    assert_eq!(key("noterminator"), None); // ditto, longer
    assert_eq!(key("api_key secret"), None); // space is not `=`/`:`/`~`
    assert_eq!(key("key|val"), None); // `|` is not an accepted terminator
}

#[test]
fn leading_non_key_byte_yields_none() {
    assert_eq!(key("=value"), None); // first byte is the terminator itself
    assert_eq!(key(" key=v"), None); // leading space => zero key bytes
    assert_eq!(key(""), None); // empty input
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin the accepted terminators and the None boundaries; these
// SWEEP the whole extractor against a full independent re-derivation. Key bytes
// are ASCII (`[A-Za-z0-9_.-]`), so `end` always lands on a char boundary, the
// slice is panic-free even when a multibyte char follows the key. No proptest
// before.

use proptest::prelude::*;

/// Source key-byte predicate: ASCII alphanumeric plus `_`/`-`/`.`.
fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

/// Independent oracle for `leading_assignment_key`: scan leading key bytes;
/// `None` if zero key bytes or the whole string is key bytes (no terminator);
/// else `Some(key)` iff the next byte is `=`/`:`/`~`.
fn oracle_key(candidate: &str) -> Option<String> {
    let bytes = candidate.as_bytes();
    let mut end = 0usize;
    while end < bytes.len() && is_key_byte(bytes[end]) {
        end += 1;
    }
    if end == 0 || end == bytes.len() {
        return None;
    }
    matches!(bytes[end], b'=' | b':' | b'~').then(|| candidate[..end].to_string())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// FULL differential over an assignment-rich alphabet (key bytes + the three
    /// terminators + space): naturally produces valid `key=value` extractions,
    /// bad-terminator `None`s, no-terminator `None`s, and leading-non-key `None`s.
    #[test]
    fn key_matches_oracle_over_assignment_alphabet(
        candidate in r"[A-Za-z0-9_.=:~ \-]{0,40}",
    ) {
        prop_assert_eq!(key(&candidate), oracle_key(&candidate));
    }

    /// The same differential over ARBITRARY Unicode, locks that a multibyte char
    /// following (or interrupting) the key stops the ASCII key-byte scan at a char
    /// boundary, so the slice never panics and still matches the oracle.
    #[test]
    fn key_matches_oracle_over_arbitrary_unicode(candidate in "(?s).{0,40}") {
        prop_assert_eq!(key(&candidate), oracle_key(&candidate));
    }
}
