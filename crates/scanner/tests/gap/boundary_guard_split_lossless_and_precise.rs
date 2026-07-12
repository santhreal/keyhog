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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin three hand-picked shapes; these SWEEP the two universal
// contracts over generated patterns. The splitter feeds the AC prefilter: a
// non-lossless split hands the caller a wrong token offset, and a strip that
// disagrees with split's `rest` half means two callers route a detector
// differently — both silent recall/perf faults. Driven only through the two
// public `*_for_test` facades; no proptest covered this before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// LOSSLESS + AGREEMENT (universal): for ANY pattern, whenever
    /// `split_leading_boundary_guard` fires it returns `(guard, rest)` that
    /// concatenate back to the EXACT input (so the caller's splice offset is
    /// exact), with a non-empty `rest` and a `guard` opened by `(?:`; and `strip`
    /// is ALWAYS exactly `split`'s `rest` half. The guard-rich alphabet exercises
    /// both the fire and no-fire branches.
    #[test]
    fn split_is_lossless_and_strip_agrees(
        pattern in r"[-()?:^|\[\]A-Za-z0-9_]{0,40}",
    ) {
        let split = split_leading_boundary_guard_for_test(&pattern);
        if let Some((guard, rest)) = &split {
            let joined = format!("{guard}{rest}");
            prop_assert_eq!(joined, pattern.clone());
            prop_assert!(!rest.is_empty(), "rest must be non-empty when split fires");
            prop_assert!(guard.starts_with("(?:"), "guard must open with (?:");
        }
        prop_assert_eq!(
            strip_leading_boundary_guard_for_test(&pattern),
            split.map(|(_, rest)| rest)
        );
    }

    /// Positive path: the real boundary-guard idiom prepended to ANY non-empty
    /// body MUST split into exactly `(idiom, body)` — the guard's own `)` closes
    /// it at depth 0 regardless of body content, so the following literal token is
    /// always surfaced to the AC set (the KH recall lever this splitter exists for).
    #[test]
    fn boundary_guard_idiom_always_splits_off_a_nonempty_body(
        body in r"[-()?:^|$A-Za-z0-9_\[\]{}]{1,30}",
    ) {
        let pattern = format!("(?:^|[^A-Za-z0-9_]){body}");
        let split = split_leading_boundary_guard_for_test(&pattern);
        prop_assert_eq!(split, Some(("(?:^|[^A-Za-z0-9_])".to_string(), body)));
    }

    /// Byte-boundary safety: the splitter parses by byte offset but must only ever
    /// return char-boundary slices, so neither `split` nor `strip` may panic on
    /// arbitrary Unicode — multi-byte chars inside a leading group, embedded
    /// newlines (`(?s)`), or a truncated `(?:` opener.
    #[test]
    fn boundary_guard_split_never_panics_on_arbitrary_unicode(
        pattern in "(?s).{0,40}",
    ) {
        let _ = split_leading_boundary_guard_for_test(&pattern);
        let _ = strip_leading_boundary_guard_for_test(&pattern);
    }
}
