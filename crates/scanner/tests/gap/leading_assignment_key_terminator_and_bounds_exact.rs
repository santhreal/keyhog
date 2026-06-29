//! Gap test: the leading-assignment-key extractor's exact key slice + bounds.
//!
//! `generic_keyword_owner::leading_assignment_key` pulls the key out of a
//! `key=value` / `key:value` / `key~value` candidate prefix so that
//! `candidate_embeds_owned_assignment_key` can ask whether a named detector
//! owns that key (e.g. is `api_key=…` owned by a generic-keyword detector). It
//! scans leading "key bytes" (ASCII alphanumeric plus `_`, `-`, `.`) and then
//! requires the very next byte to be one of `=`, `:`, `~`; otherwise — and when
//! the whole string is key bytes (no terminator) or the first byte is already a
//! non-key byte — it yields `None`.
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
