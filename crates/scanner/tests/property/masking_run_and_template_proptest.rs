//! Masking-run + bracketed-template suppression predicates
//! (`crates/scanner/src/suppression/shape/canonical.rs`).
//!
//! Three precision gates, with one deliberate — and easily-confused — divergence
//! this suite pins so a reader cannot assume the two run detectors are the same:
//!   • `has_three_or_more_consecutive_identical` counts a run of ANY byte,
//!     dashes INCLUDED (`a---b` → true).
//!   • `has_n_or_more_consecutive_identical(_, n)` EXCLUDES dash runs (dashes are
//!     legitimate delimiters in PEM/UUID/JWT), so `a---b` with n=3 → false.
//!   • `looks_like_bracketed_template_placeholder` matches a `{…}` / `<…>` / `${…}`
//!     wrapper no longer than the 80-byte placeholder cap.

use keyhog_scanner::testing::{
    has_n_or_more_consecutive_identical_for_test, has_three_or_more_consecutive_identical_for_test,
    looks_like_bracketed_template_placeholder_for_test,
};
use proptest::prelude::*;

// ── the dash divergence (the whole reason both functions exist) ───────────────

#[test]
fn dash_runs_count_for_three_but_not_for_n() {
    // `a---b`: a run of three dashes.
    assert!(has_three_or_more_consecutive_identical_for_test("a---b"));
    assert!(!has_n_or_more_consecutive_identical_for_test("a---b", 3));
    // A non-dash run of three counts for BOTH.
    assert!(has_three_or_more_consecutive_identical_for_test("axxxb"));
    assert!(has_n_or_more_consecutive_identical_for_test("axxxb", 3));
}

#[test]
fn runs_below_the_threshold_do_not_count() {
    assert!(!has_three_or_more_consecutive_identical_for_test("aabbcc")); // max run 2
    assert!(!has_n_or_more_consecutive_identical_for_test("aabb", 3));
    // n is honored: a run of exactly 4 clears n=4 but a run of 3 does not.
    assert!(has_n_or_more_consecutive_identical_for_test("axxxxb", 4));
    assert!(!has_n_or_more_consecutive_identical_for_test("axxxb", 4));
}

// ── bracketed template placeholders ──────────────────────────────────────────

#[test]
fn bracketed_placeholders_match_each_wrapper() {
    assert!(looks_like_bracketed_template_placeholder_for_test(
        "{placeholder}"
    ));
    assert!(looks_like_bracketed_template_placeholder_for_test(
        "<your-token-here>"
    ));
    assert!(looks_like_bracketed_template_placeholder_for_test(
        "${ENV_VAR}"
    ));
}

#[test]
fn unbracketed_or_oversized_values_do_not_match() {
    assert!(!looks_like_bracketed_template_placeholder_for_test(
        "ghp_realtokenshape"
    ));
    assert!(!looks_like_bracketed_template_placeholder_for_test(
        "{unterminated"
    ));
    assert!(!looks_like_bracketed_template_placeholder_for_test(
        "plain}"
    ));
    // At the 80-byte cap it matches; one over the cap it does not.
    let at_cap = format!("{{{}}}", "a".repeat(78)); // 78 + 2 braces = 80
    assert_eq!(at_cap.len(), 80);
    assert!(looks_like_bracketed_template_placeholder_for_test(&at_cap));
    let over_cap = format!("{{{}}}", "a".repeat(79)); // 81 bytes
    assert!(!looks_like_bracketed_template_placeholder_for_test(
        &over_cap
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// A NON-dash string is classified IDENTICALLY by both detectors at threshold
    /// 3 — the divergence is exclusively about dashes.
    #[test]
    fn non_dash_input_agrees_across_both_detectors(s in "[a-zA-Z0-9]{0,40}") {
        prop_assert_eq!(
            has_three_or_more_consecutive_identical_for_test(&s),
            has_n_or_more_consecutive_identical_for_test(&s, 3)
        );
    }

    /// A string of only dashes NEVER trips `has_n_or_more_consecutive_identical`
    /// for any n >= 1 (dashes are excluded), yet a run of >= 3 dashes DOES trip
    /// the three-or-more variant.
    #[test]
    fn all_dash_input_splits_the_two_detectors(len in 3usize..40, n in 1usize..8) {
        let s = "-".repeat(len);
        prop_assert!(!has_n_or_more_consecutive_identical_for_test(&s, n));
        prop_assert!(has_three_or_more_consecutive_identical_for_test(&s));
    }

    /// Monotonic in n: if a value has an n-run it also has every shorter run, so
    /// `has_n(v, k)` implies `has_n(v, k-1)` for k >= 2.
    #[test]
    fn run_detection_is_monotonic_in_n(s in "[a-z]{0,40}", k in 2usize..10) {
        if has_n_or_more_consecutive_identical_for_test(&s, k) {
            prop_assert!(has_n_or_more_consecutive_identical_for_test(&s, k - 1));
        }
    }

    /// A template match IMPLIES a recognized wrapper and length <= 80 — the gate
    /// never fires on an unbracketed or oversized value.
    #[test]
    fn template_match_implies_wrapper_and_cap(value in ".{0,100}") {
        if looks_like_bracketed_template_placeholder_for_test(&value) {
            let wrapped = (value.starts_with('{') && value.ends_with('}'))
                || (value.starts_with('<') && value.ends_with('>'))
                || (value.starts_with("${") && value.ends_with('}'));
            prop_assert!(wrapped);
            prop_assert!(value.len() <= 80);
        }
    }
}
