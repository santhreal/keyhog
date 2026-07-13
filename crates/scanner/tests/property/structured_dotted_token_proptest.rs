//! `is_structured_dotted_token` allowlist contract
//! (`crates/scanner/src/suppression/shape/canonical.rs`).
//!
//! Dots appear in real credentials (JWT `header.payload.signature`, Discord bot
//! `id.timestamp.hmac`) AND in ordinary code (`obj.field.method`, `a.b.c.d`
//! property chains, version strings). The generic-secret and entropy gates use
//! this predicate to decide which dotted values to TRUST, so it must be a tight
//! shape allowlist: exactly three dot-separated segments matching either the
//! JWT shape (first segment `eyJ…`, every segment >= 4 base64 chars) or the
//! Discord length profile (23-28 . 6-8 . 27-38, alnum/`-`/`_`). Anything else 
//! including a two- or four-segment string (is NOT a structured token).

use keyhog_scanner::testing::is_structured_dotted_token_for_test;
use proptest::prelude::*;

// ── JWT shape ────────────────────────────────────────────────────────────────

#[test]
fn a_real_jwt_is_a_structured_token() {
    // Standard RFC 7519 example JWT: three base64url segments, header starts `eyJ`.
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.\
               SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    assert!(is_structured_dotted_token_for_test(jwt));
}

#[test]
fn jwt_without_the_eyj_header_is_not_structured() {
    // Same 3-segment base64 shape but the header does NOT start with `eyJ` → not a
    // JWT, and its segment lengths don't hit the Discord profile → rejected.
    let not_jwt = "abcJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2Q";
    assert!(!is_structured_dotted_token_for_test(not_jwt));
}

#[test]
fn jwt_with_a_short_segment_is_not_structured() {
    // A segment shorter than 4 chars breaks the JWT rule.
    assert!(!is_structured_dotted_token_for_test(
        "eyJ.eyJzdWIiOiJ9.SflKxwRJSMeK"
    ));
}

// ── Discord shape ────────────────────────────────────────────────────────────

#[test]
fn a_discord_shaped_token_is_structured() {
    // 24 . 7 . 30 alnum chars (inside the (23..=28) . (6..=8) . (27..=38) profile).
    let first = "A".repeat(24);
    let second = "B".repeat(7);
    let third = "C".repeat(30);
    let token = format!("{first}.{second}.{third}");
    assert!(is_structured_dotted_token_for_test(&token));
}

#[test]
fn discord_shape_with_out_of_range_segment_is_rejected() {
    // Middle segment length 5 is below the 6..=8 window → not Discord, not JWT.
    let token = format!("{}.{}.{}", "A".repeat(24), "B".repeat(5), "C".repeat(30));
    assert!(!is_structured_dotted_token_for_test(&token));
}

// ── non-credential dotted strings ────────────────────────────────────────────

#[test]
fn property_chains_and_wrong_segment_counts_are_rejected() {
    assert!(!is_structured_dotted_token_for_test("obj.field.method")); // code chain
    assert!(!is_structured_dotted_token_for_test("a.b")); // 2 segments
    assert!(!is_structured_dotted_token_for_test("a.b.c.d")); // 4 segments
    assert!(!is_structured_dotted_token_for_test("nodothere")); // no dot at all
    assert!(!is_structured_dotted_token_for_test("")); // empty
    assert!(!is_structured_dotted_token_for_test("1.2.3")); // version
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// A structured token ALWAYS has exactly three dot-separated segments, any
    /// other segment count is rejected outright, whatever the content.
    #[test]
    fn accepted_iff_exactly_three_segments(value in "[a-zA-Z0-9._-]{0,80}") {
        if is_structured_dotted_token_for_test(&value) {
            prop_assert_eq!(value.split('.').count(), 3);
        }
    }

    /// No string WITHOUT a dot is ever a structured token (the fast-path guard).
    #[test]
    fn dotless_is_never_structured(value in "[a-zA-Z0-9_-]{0,64}") {
        prop_assert!(!is_structured_dotted_token_for_test(&value));
    }

    /// The JWT branch is exact: three `eyJ…`-headed base64 segments each >= 4 long
    /// are always accepted; the same body with a mangled (non-`eyJ`) header whose
    /// lengths miss the Discord window is always rejected.
    #[test]
    fn jwt_header_gate_is_decisive(
        payload in "[a-zA-Z0-9_-]{8,20}",
        sig in "[a-zA-Z0-9_-]{8,20}",
    ) {
        let good = format!("eyJhbGciOiJ.{payload}.{sig}");
        prop_assert!(is_structured_dotted_token_for_test(&good));
        // Swap the header to a 11-char non-eyJ segment (outside Discord's 23..=28).
        let bad = format!("zzJhbGciOiJ.{payload}.{sig}");
        prop_assert!(!is_structured_dotted_token_for_test(&bad));
    }
}
