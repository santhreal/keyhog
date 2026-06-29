//! Gap test: the leading boundary-guard splitter is lossless AND precise.
//!
//! `split_leading_boundary_guard` lets the prefix compiler see PAST the
//! `(?:^|[^A-Za-z0-9_])` boundary-guard idiom so the real literal token that
//! follows (`AKIA…`) gets pulled into the Aho-Corasick prefilter set. Its whole
//! correctness rests on two properties that had no test:
//!   - LOSSLESS: the returned `(guard, rest)` concatenates back to the input, so
//!     the token offset the caller splices is exact.
//!   - PRECISE: it fires ONLY when every leading alternative is a boundary token
//!     — a genuine prefix alternation like `(?:ghp_|github_pat_)` must be left
//!     alone, or the compiler would strip a real prefix and route the detector
//!     into the slow phase-2 path.
//! `strip_leading_boundary_guard` is just the `rest` half; pin that they agree.

use keyhog_scanner::testing::{
    split_leading_boundary_guard_for_test, strip_leading_boundary_guard_for_test,
};

#[test]
fn boundary_guard_idiom_splits_losslessly() {
    let pattern = "(?:^|[^A-Za-z0-9_])AKIA[A-Z0-9]{16}";
    let split = split_leading_boundary_guard_for_test(pattern);
    assert_eq!(
        split,
        Some((
            "(?:^|[^A-Za-z0-9_])".to_string(),
            "AKIA[A-Z0-9]{16}".to_string()
        ))
    );
    // Lossless: guard + rest reconstructs the original pattern exactly.
    let (guard, rest) = split.unwrap();
    assert_eq!(format!("{guard}{rest}"), pattern);
    // strip is exactly the rest half.
    assert_eq!(
        strip_leading_boundary_guard_for_test(pattern),
        Some("AKIA[A-Z0-9]{16}".to_string())
    );
}

#[test]
fn real_prefix_alternation_is_not_a_boundary_guard() {
    // `(?:ghp_|github_pat_)` is a real prefix alternation, NOT a boundary guard:
    // stripping it would drop the GitHub-token prefix from the AC set.
    let pattern = "(?:ghp_|github_pat_)[A-Za-z0-9_]{36}";
    assert_eq!(split_leading_boundary_guard_for_test(pattern), None);
    assert_eq!(strip_leading_boundary_guard_for_test(pattern), None);
}

#[test]
fn pattern_without_leading_group_is_untouched() {
    // No leading `(?:` group at all.
    let pattern = "AKIA[A-Z0-9]{16}";
    assert_eq!(split_leading_boundary_guard_for_test(pattern), None);
    assert_eq!(strip_leading_boundary_guard_for_test(pattern), None);
}
