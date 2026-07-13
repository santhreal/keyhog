//! `bare_auth_value_allowed` FP-suppression contract
//! (`crates/scanner/src/adjudicate/generic.rs`).
//!
//! A bare `auth = <value>` assignment is weak evidence: `auth` is a common word
//! and the value is unqualified. This gate decides which such values to keep. It
//! allows exactly two shapes:
//!   1. a structured dotted token (JWT / Discord, delegated to
//!      `is_structured_dotted_token`), or
//!   2. a DOT-FREE value that has at least one non-alphanumeric byte AND clears
//!      the secret-strength checks.
//! Everything else, a plain word, a pure-alphanumeric identifier, or any dotted
//! value that is not a real structured token (is rejected as a false positive).
//!
//! The two structural gates (needs a symbol on the dot-free path; a dotted value
//! must be a real structured token) are decidable without reproducing the
//! entropy/strength model, so they are pinned exactly here.

use keyhog_scanner::testing::bare_auth_value_allowed_for_test;
use proptest::prelude::*;

// ── the structured-token path (branch 1) ─────────────────────────────────────

#[test]
fn a_real_jwt_is_allowed_via_the_structured_path() {
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.\
               SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    assert!(bare_auth_value_allowed_for_test(jwt));
}

// ── rejections: the FP shapes ────────────────────────────────────────────────

#[test]
fn plain_words_and_identifiers_are_rejected() {
    // Dot-free, fully alphanumeric → fails the "has a non-alnum byte" gate.
    for word in [
        "password",
        "enabled",
        "true",
        "authToken",
        "abc123",
        "AUTHORIZED",
    ] {
        assert!(
            !bare_auth_value_allowed_for_test(word),
            "{word:?} is a pure-alphanumeric value and must be rejected"
        );
    }
}

#[test]
fn a_dotted_non_structured_value_is_rejected() {
    // Has dots but is NOT a JWT/Discord token → branch 1 fails (not structured) and
    // branch 2 is gated on `!value.contains('.')`, so it can never be allowed.
    assert!(!bare_auth_value_allowed_for_test("obj.field.method"));
    assert!(!bare_auth_value_allowed_for_test("v1.2.3"));
    assert!(!bare_auth_value_allowed_for_test("a.b.c.d.e"));
    // Even a strong-looking dotted secret is rejected purely on the dot rule.
    assert!(!bare_auth_value_allowed_for_test("Xk9$mQ2.pL7#wZ4.rT1@vN8"));
}

#[test]
fn empty_value_is_rejected() {
    assert!(!bare_auth_value_allowed_for_test(""));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// A DOT-FREE, fully alphanumeric value is NEVER allowed, the dot-free branch
    /// requires at least one non-alphanumeric byte, and the structured-token branch
    /// requires a dot. This invariant holds independent of the strength model.
    #[test]
    fn pure_alphanumeric_dotless_value_is_never_allowed(value in "[a-zA-Z0-9]{1,40}") {
        prop_assert!(!bare_auth_value_allowed_for_test(&value));
    }

    /// A value containing a dot that is NOT a structured token is never allowed:
    /// branch 2 is fully gated on `!contains('.')`, so any dotted value must pass
    /// the structured-token allowlist (a `.`-joined pair of plain words cannot).
    #[test]
    fn dotted_plain_words_never_allowed(
        a in "[a-z]{1,10}",
        b in "[a-z]{1,10}",
    ) {
        let value = format!("{a}.{b}"); // 2 segments → never a structured token
        prop_assert!(!bare_auth_value_allowed_for_test(&value));
    }
}
