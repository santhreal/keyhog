//! Gap test: the named-detector owner OR-composition.
//!
//! `generic_keyword_owner::candidate_embeds_owned_assignment_key` is the top
//! decision the generic `KEY=value` bridge uses to decide a candidate is already
//! owned by a named detector. It composes the two pinned helpers:
//!   - empty owned set -> not owned;
//!   - `leading_assignment_key` returns None (no `=`/`:`/`~` terminator) ->
//!     fall back to the prefix-embed check on the whole candidate;
//!   - terminator present -> the leading key is owned EXACTLY, OR the whole
//!     candidate prefix-embeds an owned key.
//!
//! All vectors were traced through `leading_assignment_key`,
//! `assignment_keyword_owned_by_named_detector`, and
//! `candidate_starts_with_owned_assignment_key`.

use keyhog_scanner::testing::candidate_embeds_owned_assignment_key_for_test as embeds;

#[test]
fn the_exact_owned_assignment_key_before_a_terminator_is_owned() {
    // Leading key `api_key` is owned exactly (first disjunct).
    assert!(embeds(&["api_key"], "api_key=AKIAEXAMPLE"));
}

#[test]
fn a_vendor_suffixed_key_is_owned_via_the_prefix_embed_disjunct() {
    // Leading key `api_key_v2` is NOT owned exactly (the `v2` suffix fails the
    // credential-suffix gate), but the candidate prefix-embeds `api_key`, so the
    // second disjunct claims ownership.
    assert!(embeds(&["api_key"], "api_key_v2=xxx"));
}

#[test]
fn a_candidate_without_a_terminator_falls_back_to_the_prefix_embed() {
    // No `=`/`:`/`~`, so `leading_assignment_key` is None and the fallback runs.
    assert!(embeds(&["api_key"], "api_key_extra"));
    assert!(!embeds(&["api_key"], "other_value"));
}

#[test]
fn an_unowned_key_or_empty_owned_set_is_not_owned() {
    // Terminator present, but neither disjunct matches.
    assert!(!embeds(&["api_key"], "username=bob"));
    // Empty owned set owns nothing.
    assert!(!embeds(&[], "api_key=xxx"));
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin each disjunct and the no-terminator fallback; these SWEEP
// the COMPOSITION as CROSS-FACADE differentials (real truth, not a mirror of the
// source): the empty set owns nothing; `embeds` is a strict SUPERSET of the
// prefix-embed check (that check is a disjunct in BOTH the terminator and
// no-terminator branches); when the candidate has no `=`/`:`/`~` terminator,
// `embeds` reduces EXACTLY to the prefix-embed check; the decision is monotone in
// the owned set; and it never panics. No proptest before.

use keyhog_scanner::testing::{
    candidate_starts_with_owned_assignment_key_for_test as starts_with_owned,
    leading_assignment_key_for_test as leading_key,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// The empty owned set owns nothing, for any candidate.
    #[test]
    fn empty_owned_set_never_embeds(candidate in "(?s).{0,40}") {
        prop_assert!(!embeds(&[], &candidate));
    }

    /// `embeds` is a SUPERSET of the prefix-embed check: whenever the candidate
    /// prefix-embeds an owned key, `embeds` is true (prefix-embed is a disjunct in
    /// both the terminator and no-terminator branches).
    #[test]
    fn embeds_is_a_superset_of_prefix_embed(
        candidate in "[A-Za-z0-9_.=:~-]{0,32}",
        owned in prop::collection::vec("[a-z_]{1,12}", 0..4),
    ) {
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        prop_assert!(!starts_with_owned(&refs, &candidate) || embeds(&refs, &candidate));
    }

    /// With NO leading `=`/`:`/`~` terminator, `leading_assignment_key` is None, so
    /// `embeds` reduces EXACTLY to the prefix-embed check — the exact-leading-key
    /// disjunct is unreachable.
    #[test]
    fn no_terminator_reduces_to_prefix_embed(
        candidate in "[A-Za-z0-9_.-]{0,32}",
        owned in prop::collection::vec("[a-z_]{1,12}", 0..4),
    ) {
        prop_assume!(leading_key(&candidate).is_none());
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        prop_assert_eq!(embeds(&refs, &candidate), starts_with_owned(&refs, &candidate));
    }

    /// Monotone in the owned set: adding owned keys can only ADD ownership (both
    /// disjuncts — exact membership and prefix-embed — grow with the set).
    #[test]
    fn embeds_is_monotone_in_the_owned_set(
        candidate in "[A-Za-z0-9_.=:~-]{0,32}",
        owned in prop::collection::vec("[a-z_]{1,12}", 0..3),
        extra in prop::collection::vec("[a-z_]{1,12}", 0..3),
    ) {
        let base_refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        let base = embeds(&base_refs, &candidate);
        let mut sup: Vec<&str> = base_refs.clone();
        sup.extend(extra.iter().map(|s| s.as_str()));
        let sup_res = embeds(&sup, &candidate);
        prop_assert!(!base || sup_res); // base => sup
    }

    /// Never panics on arbitrary Unicode candidate + arbitrary owned keys.
    #[test]
    fn never_panics_on_arbitrary_input(
        candidate in "(?s).{0,40}",
        owned in prop::collection::vec("(?s).{0,12}", 0..4),
    ) {
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        let _ = embeds(&refs, &candidate);
    }
}
