//! Gap test: the named-detector owner check with assignment-key span expansion.
//!
//! `generic_keyword_owner::keyword_span_owned_by_named_detector` decides whether
//! the assignment key a generic match landed on is already owned by a named
//! detector. It (1) rejects an out-of-bounds span, (2) checks the exact
//! `[keyword_start, keyword_end)` slice, then (3) expands the span left and right
//! over `is_assignment_key_byte` characters and re-checks ONLY the expanded span
//! — so a regex that captured just `key` inside `vendor_api_key` still resolves
//! ownership of the full key.
//!
//! The helper had no direct coverage. Pin the bounds guard, the exact-span hit,
//! both expansion directions, and that a full-boundary span that is not owned
//! stays unowned (no spurious re-check). Owned keywords are supplied already
//! normalized; the facade sorts/dedups them through the real `BTreeSet` path.
//! All vectors were traced through the normalize -> secret-suffix -> membership
//! chain.

use keyhog_scanner::testing::keyword_span_owned_by_named_detector_for_test as span_owned;

#[test]
fn an_exact_span_that_is_owned_resolves_without_expansion() {
    assert!(span_owned(&["api_key"], "api_key", 0, 7));
}

#[test]
fn the_span_expands_left_and_right_to_the_full_assignment_key() {
    // Regex captured only `key` (indices 11..14) inside `vendor_api_key`;
    // expanding left reaches the owned full key.
    assert!(span_owned(&["vendor_api_key"], "vendor_api_key", 11, 14));
    // Captured only `api` (indices 0..3); expanding right reaches `api_key`.
    assert!(span_owned(&["api_key"], "api_key", 0, 3));
}

#[test]
fn a_full_boundary_unowned_span_is_not_owned() {
    // The span already spans the whole key, so expansion cannot change it and
    // an unowned key stays unowned.
    assert!(!span_owned(&["other_key"], "api_key", 0, 7));
    // The span expands to `vendor_api_key`, which is not in the owned set.
    assert!(!span_owned(&["zzz_secret"], "vendor_api_key", 11, 14));
}

#[test]
fn out_of_bounds_spans_are_rejected() {
    assert!(!span_owned(&["api_key"], "api_key", 5, 2)); // start > end
    assert!(!span_owned(&["api_key"], "api_key", 0, 8)); // end > line length
}
