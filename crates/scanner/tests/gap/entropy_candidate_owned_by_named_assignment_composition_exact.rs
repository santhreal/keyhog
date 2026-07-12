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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin each branch; these SWEEP the COMPOSITION as a CROSS-FACADE
// differential (real truth, not a source mirror): both disjuncts are delegated to
// their own facades, so the oracle tests only the OR wiring — `candidate_owned` is
// exactly `embeds(candidate) OR (same_line present AND its keyword owned)`. Plus
// empty-set-owns-nothing, monotone-in-owned-set, and no-panic. Traced against
// generic_keyword_owner.rs:171. No proptest before.

use keyhog_scanner::testing::{
    candidate_embeds_owned_assignment_key_for_test as embeds,
    line_assignment_owned_by_named_detector_for_test as line_owned,
};
use proptest::prelude::*;

/// The exact OR composition, each disjunct delegated to its own tested facade.
fn oracle(owned: &[&str], candidate: &str, same_line: Option<&str>) -> bool {
    embeds(owned, candidate) || same_line.is_some_and(|l| line_owned(owned, l))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// FULL differential over assignment-shaped candidates / same-lines and
    /// arbitrary owned sets.
    #[test]
    fn matches_the_or_composition(
        candidate in "[A-Za-z0-9_.=:~ -]{0,40}",
        owned in prop::collection::vec("[a-z_]{1,12}", 0..4),
        same in prop::option::of("[A-Za-z0-9_.=:~ -]{0,40}"),
    ) {
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        let same_ref = same.as_deref();
        prop_assert_eq!(
            candidate_owned(&refs, &candidate, same_ref),
            oracle(&refs, &candidate, same_ref)
        );
    }

    /// The same differential over arbitrary Unicode (no-panic + agreement).
    #[test]
    fn matches_the_or_composition_on_arbitrary_unicode(
        candidate in "(?s).{0,32}",
        owned in prop::collection::vec("(?s).{0,10}", 0..4),
        same in prop::option::of("(?s).{0,32}"),
    ) {
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        let same_ref = same.as_deref();
        prop_assert_eq!(
            candidate_owned(&refs, &candidate, same_ref),
            oracle(&refs, &candidate, same_ref)
        );
    }

    /// The empty owned set owns nothing, regardless of candidate or same-line.
    #[test]
    fn empty_owned_set_never_owns(
        candidate in "(?s).{0,32}",
        same in prop::option::of("(?s).{0,32}"),
    ) {
        prop_assert!(!candidate_owned(&[], &candidate, same.as_deref()));
    }

    /// Monotone in the owned set: adding owned keys can only ADD ownership.
    #[test]
    fn monotone_in_owned_set(
        candidate in "[A-Za-z0-9_.=:~ -]{0,40}",
        owned in prop::collection::vec("[a-z_]{1,12}", 0..3),
        extra in prop::collection::vec("[a-z_]{1,12}", 0..3),
        same in prop::option::of("[A-Za-z0-9_.=:~ -]{0,40}"),
    ) {
        let base_refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        let same_ref = same.as_deref();
        let base = candidate_owned(&base_refs, &candidate, same_ref);
        let mut sup: Vec<&str> = base_refs.clone();
        sup.extend(extra.iter().map(|s| s.as_str()));
        prop_assert!(!base || candidate_owned(&sup, &candidate, same_ref)); // base => sup
    }
}
