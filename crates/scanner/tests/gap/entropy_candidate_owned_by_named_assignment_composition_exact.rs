//! Gap test: the top entropy-candidate named-detector owner composition.
//!
//! `generic_keyword_owner::entropy_candidate_owned_by_named_assignment` is the
//! entry the entropy path uses to decide a candidate is already owned by a named
//! detector. It is the OR of two pinned helpers:
//!   - `candidate_embeds_owned_assignment_key(owned, candidate)`; and
//!   - when a `same_line` is supplied, `line_assignment_owned_by_named_detector`.
//!
//! Contract: an embedding candidate short-circuits (the same-line is never
//! consulted); a non-embedding candidate falls to the same-line check, which is
//! false when there is no same-line and otherwise reflects whether that line's
//! assignment keyword is owned; an empty owned set owns nothing (both inner
//! paths guard on it). All vectors were traced through both helpers.

use keyhog_scanner::testing::entropy_candidate_owned_by_named_assignment_for_test as candidate_owned;

#[test]
fn an_embedding_candidate_short_circuits_and_ignores_same_line() {
    // `api_key=x` embeds the owned key, so ownership holds even with no same-line.
    assert!(candidate_owned(&["api_key"], "api_key=x", None));
}

#[test]
fn a_non_embedding_candidate_falls_to_the_same_line_check() {
    // No same-line and the candidate does not embed -> not owned.
    assert!(!candidate_owned(&["api_key"], "randomvalue", None));
    // Same-line whose selected keyword is owned -> owned.
    assert!(candidate_owned(
        &["api_key"],
        "randomvalue",
        Some("api_key=secret")
    ));
}

#[test]
fn a_non_embedding_candidate_with_an_unowned_same_line_keyword_is_not_owned() {
    assert!(!candidate_owned(
        &["api_key"],
        "randomvalue",
        Some("other_key=val")
    ));
}

#[test]
fn an_empty_owned_set_owns_nothing() {
    assert!(!candidate_owned(&[], "api_key=x", Some("api_key=secret")));
}
