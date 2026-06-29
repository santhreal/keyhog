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
