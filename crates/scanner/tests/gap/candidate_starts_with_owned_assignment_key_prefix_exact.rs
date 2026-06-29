//! Gap test: the prefix-embed fallback of the named-detector owner check.
//!
//! `generic_keyword_owner::candidate_starts_with_owned_assignment_key` is the
//! fallback used when a generic candidate has no clean `KEY=value` split: the
//! candidate is owned if it normalizes to a STRICTLY longer key that begins with
//! one of the owned keys AND that owned key itself carries a credential suffix
//! (`*_key`, `*_secret`, ...). All three conjuncts are load-bearing:
//!   - strict length (`>`, not `>=`): an exact match is not a prefix-embed;
//!   - `starts_with`: a byte-level prefix, not a substring/contains;
//!   - the owned key's secret suffix: a bare service marker like `service` never
//!     claims ownership of everything that starts with it.
//!
//! The helper had no direct coverage. All vectors were traced through
//! `normalize_assignment_keyword` and `normalized_assignment_keyword_has_secret_suffix`.

use keyhog_scanner::testing::candidate_starts_with_owned_assignment_key_for_test as starts_with_owned;

#[test]
fn a_longer_candidate_with_an_owned_secret_suffixed_prefix_is_owned() {
    assert!(starts_with_owned(&["api_key"], "api_key_extra"));
    assert!(starts_with_owned(
        &["segment_write_key"],
        "segment_write_key_id"
    ));
}

#[test]
fn an_exact_length_match_is_not_a_prefix_embed() {
    // `>` not `>=`: equal-length is the exact-membership path's job, not this one.
    assert!(!starts_with_owned(&["api_key"], "api_key"));
}

#[test]
fn a_prefix_whose_owned_key_lacks_a_secret_suffix_is_not_owned() {
    // `service` is a bare service marker, not a credential slot, so it never
    // claims ownership of `service_account`.
    assert!(!starts_with_owned(&["service"], "service_account"));
}

#[test]
fn a_non_prefix_match_or_empty_set_or_unnormalizable_candidate_is_not_owned() {
    // Contains the owned key but does not start with it.
    assert!(!starts_with_owned(&["api_key"], "my_api_key_x"));
    // Empty owned set owns nothing.
    assert!(!starts_with_owned(&[], "api_key_extra"));
    // Candidate normalizes to empty (no alphanumerics) -> None -> not owned.
    assert!(!starts_with_owned(&["api_key"], "=="));
}
