//! Standalone unit coverage for the public suppression shape gates, reached via
//! `keyhog_scanner::testing::shape::*` (the module is `pub(crate)`).
//!
//! These predicates decide whether a captured value is a grammar token /
//! decorated identifier rather than a real credential body. Tests assert the
//! exact true/false verdict for each documented FP family AND the negative
//! twin (a real credential of similar surface shape must NOT be suppressed) —
//! never `is_empty`/single-direction decoration.

use keyhog_scanner::testing::shape::{
    looks_like_credential_colliding_punctuation, looks_like_punctuation_decorated_identifier,
    looks_like_syntactic_punctuation_marker,
};
// `looks_like_standard_base64_blob` is exposed directly in `testing`.
use keyhog_scanner::testing::looks_like_standard_base64_blob;

// ---------------------------------------------------------------------------
// looks_like_syntactic_punctuation_marker (Tier A)
// ---------------------------------------------------------------------------

#[test]
fn double_dash_cli_flag_is_marker() {
    assert!(looks_like_syntactic_punctuation_marker("--api-secret"));
    assert!(looks_like_syntactic_punctuation_marker("--api-key"));
}

#[test]
fn single_dash_token_is_not_marker() {
    // `xoxb-...` style tokens lead with a single dash segment, NOT `--`.
    assert!(!looks_like_syntactic_punctuation_marker(
        "xoxb-1234567890-abcdefABCDEF"
    ));
}

#[test]
fn pem_dashes_are_not_marker() {
    // 5 leading dashes = PEM marker, a legitimate private-key positive.
    assert!(!looks_like_syntactic_punctuation_marker("-----BEGIN"));
}

#[test]
fn pointer_and_attribute_sigils_are_markers() {
    assert!(looks_like_syntactic_punctuation_marker("&gss_recv_token")); // C pointer
    assert!(looks_like_syntactic_punctuation_marker("@api_key")); // attribute
    assert!(looks_like_syntactic_punctuation_marker("$API_KEY")); // shell var
}

#[test]
fn sigil_with_credential_symbols_is_not_marker() {
    // A real secret that merely starts with a sigil but carries credential
    // symbols (`%`, `!`, `+`, `-`) is NOT a bare identifier marker.
    assert!(!looks_like_syntactic_punctuation_marker(
        "@gAdtFo%B!tcnSl+A-Rt5x"
    ));
}

#[test]
fn trailing_colon_label_is_marker() {
    assert!(looks_like_syntactic_punctuation_marker("Password:"));
    assert!(looks_like_syntactic_punctuation_marker("Username:"));
}

#[test]
fn trailing_colon_after_nonalpha_is_not_marker() {
    // `sha256:...` is not pure-alpha before the colon -> not this marker.
    assert!(!looks_like_syntactic_punctuation_marker("abc123:"));
}

#[test]
fn empty_value_is_not_marker() {
    assert!(!looks_like_syntactic_punctuation_marker(""));
}

// ---------------------------------------------------------------------------
// looks_like_credential_colliding_punctuation (Tier B)
// ---------------------------------------------------------------------------

#[test]
fn leading_slash_or_bang_collides() {
    assert!(looks_like_credential_colliding_punctuation("/ZM9abcd")); // base64 body OR path
    assert!(looks_like_credential_colliding_punctuation("!!token")); // JS coercion OR secret
}

#[test]
fn ts_non_null_identifier_collides() {
    // `privateAccessToken!` - TS non-null assertion on a camelCase token name.
    assert!(looks_like_credential_colliding_punctuation(
        "privateAccessToken!"
    ));
}

#[test]
fn password_with_trailing_bang_does_not_collide() {
    // `SnowFlakePass123!` has a digit -> NOT a TS-identifier; a real password.
    assert!(!looks_like_credential_colliding_punctuation(
        "SnowFlakePass123!"
    ));
}

#[test]
fn plain_credential_body_does_not_collide() {
    assert!(!looks_like_credential_colliding_punctuation(
        "ghp_abcdefghij0123456789"
    ));
}

#[test]
fn empty_value_does_not_collide() {
    assert!(!looks_like_credential_colliding_punctuation(""));
}

// ---------------------------------------------------------------------------
// looks_like_punctuation_decorated_identifier (combined Tier A + B)
// ---------------------------------------------------------------------------

#[test]
fn combined_is_union_of_both_halves() {
    // Tier-A only:
    assert!(looks_like_punctuation_decorated_identifier("--api-secret"));
    // Tier-B only:
    assert!(looks_like_punctuation_decorated_identifier("/ZM9abcd"));
    // Real credential: neither half -> false.
    assert!(!looks_like_punctuation_decorated_identifier(
        "ghp_abcdefghij0123456789"
    ));
}

#[test]
fn combined_matches_each_half_exactly() {
    // The combined predicate must equal the OR of its two documented halves
    // for a representative spread of inputs.
    let cases = [
        "--api-key",
        "@api_key",
        "/base64body",
        "!!coerced",
        "privateAccessToken!",
        "ghp_abcdefghij0123456789",
        "SnowFlakePass123!",
        "Password:",
        "",
    ];
    for c in cases {
        let combined = looks_like_punctuation_decorated_identifier(c);
        let union = looks_like_syntactic_punctuation_marker(c)
            || looks_like_credential_colliding_punctuation(c);
        assert_eq!(combined, union, "mismatch for {c:?}");
    }
}

// ---------------------------------------------------------------------------
// looks_like_standard_base64_blob
// ---------------------------------------------------------------------------

#[test]
fn standard_base64_blob_detected() {
    use base64::Engine;
    // `is_random_base64_blob(_, 40, 80, 32)` (the single source of truth this
    // delegates to) admits a blob via ANY of: `+/` punctuation, `=` padding, or
    // >=32 distinct alphanumeric chars on a mult-of-4 length. The previous
    // fixture (`[0x5A; 48]`) encoded to `WlpaWlpa…` — only 4 distinct chars, no
    // punctuation, no padding — so it correctly FAILED all three admit clauses
    // and this assertion was a stale false-positive expectation.
    //
    // Cover the two non-degenerate admit paths with real blobs:
    //   (a) DIVERSITY: a 64-char (mult-of-4), no-padding, no-`+/` blob whose
    //       alphabet diversity clears the 32-distinct floor (62 distinct alnum
    //       here: A-Z a-z 0-9 + "AB" to reach length 64).
    let diverse_blob = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB";
    assert_eq!(
        diverse_blob.len(),
        64,
        "fixture sanity: 64 is in [40,80] and mult-of-4"
    );
    assert!(
        looks_like_standard_base64_blob(diverse_blob),
        "{diverse_blob} (62-distinct-char 64-len blob) should look like a standard base64 blob"
    );
    //   (b) PADDING: 47 bytes -> a 64-char blob ending in `=` padding.
    let padded_blob = base64::engine::general_purpose::STANDARD.encode([0xABu8; 47]);
    assert!(
        padded_blob.ends_with('='),
        "fixture sanity: 47 bytes must produce `=` padding"
    );
    assert!(
        looks_like_standard_base64_blob(&padded_blob),
        "{padded_blob} (padded 64-char blob) should look like a standard base64 blob"
    );
}

#[test]
fn short_token_is_not_base64_blob() {
    // A short service token is not a long uniform base64 blob.
    assert!(!looks_like_standard_base64_blob("ghp_short"));
}
