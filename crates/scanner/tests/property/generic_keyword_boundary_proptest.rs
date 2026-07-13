//! Generic-bridge keyword left-boundary contract
//! (`crates/scanner/src/adjudicate/generic.rs`).
//!
//! The generic secret bridge fires on assignment keywords. Two of them. `pass`
//! and `auth`: are substrings of common non-secret words (`bypass`, `compass`,
//! `author`, `oauth`), so they require a whole-word left boundary before the
//! bridge will trust them. `keyword_has_word_boundary` admits a real word start
//! (line start, a non-letter neighbor, or a camelCase hinge `…yPass`) while
//! rejecting a substring tail (`bypass`). Getting this wrong is either an FP flood
//! (`bypass` → "pass" secret) or a recall hole (`myPassword` missed), so the exact
//! truth table is pinned here.

use keyhog_scanner::testing::{
    generic_bridge_keyword_requires_word_boundary_for_test, keyword_has_word_boundary_for_test,
};
use proptest::prelude::*;

// ── which keywords demand the boundary ───────────────────────────────────────

#[test]
fn only_pass_and_auth_require_a_word_boundary() {
    for require in ["pass", "auth", "PASS", "Auth"] {
        assert!(
            generic_bridge_keyword_requires_word_boundary_for_test(require),
            "{require} is substring-ambiguous and must require a boundary"
        );
    }
    for free in ["token", "secret", "apikey", "password", ""] {
        assert!(
            !generic_bridge_keyword_requires_word_boundary_for_test(free),
            "{free} is distinctive and must NOT require a boundary"
        );
    }
}

// ── the boundary truth table ─────────────────────────────────────────────────

#[test]
fn line_start_is_a_boundary() {
    assert!(keyword_has_word_boundary_for_test("password", 0));
}

#[test]
fn non_letter_neighbor_is_a_boundary() {
    // "my_pass": 'pass' begins at index 3, right after '_' (a non-letter) → boundary.
    assert!(keyword_has_word_boundary_for_test("my_pass", 3));
    assert!(keyword_has_word_boundary_for_test("X pass", 2)); // after a space
}

#[test]
fn camelcase_hinge_is_a_boundary() {
    // "myPass": lowercase 'y' immediately before uppercase 'P' → camelCase word start.
    assert!(keyword_has_word_boundary_for_test("myPass", 2));
}

#[test]
fn substring_tail_is_not_a_boundary() {
    // "bypass": lowercase 'y' before lowercase 'p' → 'pass' is a mid-word tail, NOT
    // a boundary. This is the FP the whole gate exists to reject.
    assert!(!keyword_has_word_boundary_for_test("bypass", 2));
    assert!(!keyword_has_word_boundary_for_test("compass", 3));
}

#[test]
fn uppercase_prev_letter_is_not_a_camelcase_hinge() {
    // Only lowercase→UPPERCASE is a hinge; 'P' before 'P' ("APPass" style) is not.
    assert!(!keyword_has_word_boundary_for_test("XPass", 1));
}

#[test]
fn offset_past_end_defaults_to_boundary_preserving_recall() {
    // A zero-width / out-of-range match offset must NOT suppress (recall-preserving,
    // Law 10 note in the source): treat as a boundary.
    assert!(keyword_has_word_boundary_for_test("abc", 10)); // keyword_start-1 out of range
    assert!(keyword_has_word_boundary_for_test("myP", 3)); // keyword_first out of range
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// `keyword_start == 0` is ALWAYS a boundary, for any line.
    #[test]
    fn start_of_line_is_always_a_boundary(line in ".{0,64}") {
        prop_assert!(keyword_has_word_boundary_for_test(&line, 0));
    }

    /// If the byte immediately before the keyword is a non-letter (here a digit or
    /// underscore), it is ALWAYS a boundary regardless of what follows.
    #[test]
    fn non_letter_prefix_is_always_a_boundary(
        sep in "[0-9_./ -]",
        kw in "[a-zA-Z]{1,8}",
    ) {
        let line = format!("{sep}{kw}");
        // keyword starts right after the 1-byte separator.
        prop_assert!(keyword_has_word_boundary_for_test(&line, sep.len()));
    }

    /// A lowercase letter directly before a lowercase keyword char is NEVER a
    /// boundary (the `bypass` family) (the camelCase hinge needs an uppercase head).
    #[test]
    fn lower_then_lower_is_never_a_boundary(
        head in "[a-z]{1,6}",
        kw in "[a-z]{1,8}",
    ) {
        let line = format!("{head}{kw}");
        prop_assert!(!keyword_has_word_boundary_for_test(&line, head.len()));
    }
}
