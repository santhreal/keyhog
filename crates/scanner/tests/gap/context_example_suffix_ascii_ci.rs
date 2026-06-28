//! is_known_example_credential's EXAMPLE/EXAMPLEKEY suffix check is a
//! zero-alloc ASCII-case-insensitive compare (Law 7 — no per-candidate Unicode
//! to_uppercase()). This pins that it stays byte-identical to the old
//! `to_uppercase().ends_with("EXAMPLE")` form: ASCII-case-insensitive, anchored
//! at the END, and unaffected by non-ASCII bytes earlier in the credential.

use keyhog_scanner::testing::context::is_known_example_credential;

#[test]
fn context_example_suffix_matches_case_insensitively_without_unicode_uppercase() {
    // Canonical AWS docs key — ends in EXAMPLE.
    assert!(is_known_example_credential("AKIAIOSFODNN7EXAMPLE"));
    // Mixed/lower case still matches (ASCII-case-insensitive).
    assert!(is_known_example_credential("AKIAIOSFODNN7example"));
    assert!(is_known_example_credential("akiaiosfodnn7eXaMpLe"));
    // EXAMPLEKEY is a distinct suffix (does NOT end in EXAMPLE) and must match.
    assert!(is_known_example_credential("MY_DOCS_TOKEN_EXAMPLEKEY"));
    assert!(is_known_example_credential("my_docs_token_examplekey"));

    // A non-ASCII byte earlier in the credential must not change the trailing
    // ASCII suffix decision — this is the case the old Unicode to_uppercase()
    // path and the new ascii_ci path must agree on.
    assert!(is_known_example_credential("café_secret_EXAMPLE"));

    // The suffix is END-anchored: EXAMPLE not at the end does not trip this arm
    // (and the body here is otherwise non-placeholder), and a non-ASCII tail is
    // not the ASCII suffix.
    assert!(!is_known_example_credential("EXAMPLE_prod_live_token_9f3k2"));
    assert!(!is_known_example_credential("realtokenbody0123456789"));
    assert!(!is_known_example_credential("secret_value_café"));
}
