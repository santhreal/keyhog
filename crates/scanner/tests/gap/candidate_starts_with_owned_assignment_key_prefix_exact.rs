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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin the three conjuncts and each None boundary; these SWEEP
// them as IMPLEMENTATION-INDEPENDENT invariants (deliberately NOT a mirror-oracle
// that would replicate any source bug): the empty set owns nothing; a secret-
// suffixed owned key that strictly prefixes a longer candidate IS owned (recall);
// a candidate normalizing to exactly the owned key is NOT a prefix-embed (`>`,
// not `>=`); a bare service marker without a credential suffix never owns; the
// decision is monotone in the owned set; and it never panics on arbitrary
// Unicode. No proptest before.

use proptest::prelude::*;

/// Owned keys already in normalized form that carry a real credential suffix 
/// each MUST own any strictly-longer candidate that begins with it.
const SUFFIXED: &[&str] = &[
    "api_key",
    "client_secret",
    "access_token",
    "db_password",
    "user_pwd",
    "svc_passwd",
];

/// Owned keys that are BARE service markers (no `key`/`secret`/`token`/
/// `password`/`pwd`/`passwd` suffix) (they never claim ownership of anything).
const UNSUFFIXED: &[&str] = &["service", "vendor", "config", "region", "profile"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// The empty owned set owns nothing, for any candidate.
    #[test]
    fn empty_owned_set_never_owns(candidate in "(?s).{0,40}") {
        prop_assert!(!starts_with_owned(&[], &candidate));
    }

    /// RECALL: a secret-suffixed owned key that strictly prefixes the candidate
    /// (`key_<tail>`, which normalizes to itself) is owned.
    #[test]
    fn a_secret_suffixed_prefix_of_a_longer_candidate_is_owned(
        i in 0usize..SUFFIXED.len(),
        tail in "[a-z0-9]{1,10}",
    ) {
        let key = SUFFIXED[i];
        let candidate = format!("{key}_{tail}");
        prop_assert!(starts_with_owned(&[key], &candidate));
    }

    /// A candidate that normalizes to EXACTLY the owned key is not a prefix-embed
    /// (`>`, not `>=`) (that is the exact-membership path's job, not this one).
    #[test]
    fn an_exact_normalized_match_is_not_a_prefix_embed(i in 0usize..SUFFIXED.len()) {
        let key = SUFFIXED[i];
        prop_assert!(!starts_with_owned(&[key], key));
    }

    /// A bare service marker (no credential suffix) never owns, no matter what a
    /// candidate that begins with it looks like, the suffix gate is on the OWNED
    /// key, not the candidate.
    #[test]
    fn an_unsuffixed_owned_key_never_owns(
        i in 0usize..UNSUFFIXED.len(),
        tail in "[a-z0-9_]{0,12}",
    ) {
        let key = UNSUFFIXED[i];
        let candidate = format!("{key}{tail}");
        prop_assert!(!starts_with_owned(&[key], &candidate));
    }

    /// Monotone in the owned set: adding more owned keys can only ADD ownership,
    /// never remove it (`any` over a superset). Swept over arbitrary candidates so
    /// the implication is tested for both owned and unowned base cases.
    #[test]
    fn ownership_is_monotone_in_the_owned_set(
        i in 0usize..SUFFIXED.len(),
        candidate in "[a-z0-9_]{0,24}",
        extra in prop::collection::vec("[a-z_]{1,8}", 0..3),
    ) {
        let key = SUFFIXED[i];
        let base = starts_with_owned(&[key], &candidate);
        let mut superset: Vec<&str> = extra.iter().map(|s| s.as_str()).collect();
        superset.push(key);
        let sup = starts_with_owned(&superset, &candidate);
        prop_assert!(!base || sup); // base => sup
    }

    /// Never panics on arbitrary Unicode candidate + arbitrary owned keys.
    #[test]
    fn never_panics_on_arbitrary_input(
        candidate in "(?s).{0,40}",
        owned in prop::collection::vec("(?s).{0,12}", 0..4),
    ) {
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        let _ = starts_with_owned(&refs, &candidate);
    }
}
