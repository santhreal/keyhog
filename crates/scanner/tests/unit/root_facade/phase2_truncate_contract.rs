//! Contract for `truncate_for_prefilter` — the prefilter input-truncation that
//! keeps the always-active RegexSet on the lazy-DFA instead of falling to PikeVM
//! on `{N,}`/`+`/`*` bodies. Moved out of `engine/phase2_truncate.rs` so
//! scanner src stays free of inline test modules (KH-GAP-004); driven through
//! the crate-root re-export.
//!
//! Soundness pin: truncation is a SOUND SUPERSET presence gate — it may only
//! drop a trailing bounded suffix, never widen the prefix, so the full-pattern
//! extraction still filters any over-mark. These cases assert the exact
//! truncated forms (Law 6), not merely "is/!is_none".

use keyhog_scanner::testing::truncate_for_prefilter;

#[test]
fn invalid_regex_returns_none() {
    // Parse failure path must return None rather than panic or silently weaken.
    assert!(truncate_for_prefilter("[").is_none());
}

#[test]
fn bounded_range_is_not_truncated() {
    // Already bounded `{3,5}` → no unbounded repetition to truncate → use verbatim.
    assert!(truncate_for_prefilter(r"[a-z]{3,5}").is_none());
}

#[test]
fn at_least_range_truncated_to_minimum() {
    // `{3,}` is bounded to its minimum `{3}` — exact, not a superset.
    assert_eq!(truncate_for_prefilter(r"[a-z]{3,}").unwrap(), r"[a-z]{3}");
}

#[test]
fn one_or_more_truncated_to_single() {
    // `+` (== `{1,}`) collapses to a single occurrence.
    assert_eq!(truncate_for_prefilter(r"[a-z]+").unwrap(), r"[a-z]");
}

#[test]
fn zero_or_more_drops_repeated_expr() {
    // `*` (== `{0,}`) drops the repeated expr entirely (minimum 0 occurrences).
    assert_eq!(truncate_for_prefilter(r"[a-z]*").unwrap(), "");
}
