//! Gap test: the named-detector owner binary-search is an EXACT match.
//!
//! `generic_keyword_owner::normalized_assignment_keyword_owned_by_named_detector`
//! decides whether a normalized assignment key is already owned by a loaded
//! named detector, so the broad generic `KEY=value` bridge does not second-guess
//! it. It is a `binary_search` over a sorted, deduped `&[Arc<str>]` (the real
//! builder collects through a `BTreeSet`), so ownership is EXACT membership 
//! never a prefix, superstring, or substring, and case-sensitive.
//!
//! The helper had no direct coverage. The facade sorts/dedups the supplied
//! keywords through the same `BTreeSet`, so these vectors pass an intentionally
//! UNSORTED list and still resolve correctly, pinning both the exact-match
//! contract and that the sorted-input precondition is honored. All vectors were
//! traced as plain set membership.

use keyhog_scanner::testing::assignment_keyword_owned_by_named_detector_for_test as owned;

// Deliberately unsorted: the facade/builder sorts via BTreeSet before the search.
const KEYS: &[&str] = &["segment_write_key", "api_key", "db_secret"];

#[test]
fn exact_owned_keys_are_found_regardless_of_input_order() {
    assert!(owned(KEYS, "api_key"));
    assert!(owned(KEYS, "db_secret"));
    assert!(owned(KEYS, "segment_write_key"));
}

#[test]
fn a_prefix_superstring_or_substring_is_not_owned() {
    assert!(!owned(KEYS, "api")); // prefix of api_key
    assert!(!owned(KEYS, "api_k")); // longer prefix
    assert!(!owned(KEYS, "api_key_v2")); // superstring of api_key
    assert!(!owned(KEYS, "write")); // substring of segment_write_key
    assert!(!owned(KEYS, "service_token")); // simply absent
}

#[test]
fn ownership_is_case_sensitive() {
    // The caller normalizes to lowercase before this check; an upper-cased query
    // is a different byte string and is not owned.
    assert!(!owned(KEYS, "API_KEY"));
}

#[test]
fn empty_owned_set_and_single_entry_boundaries() {
    assert!(!owned(&[], "api_key")); // nothing is owned
    assert!(owned(&["key"], "key")); // single exact entry
    assert!(!owned(&["key"], "keys")); // superstring
    assert!(!owned(&["key"], "ke")); // prefix
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin hand-picked keys; these SWEEP the ownership decision
// against a naive membership oracle. This gate decides whether the broad generic
// `KEY=value` bridge defers to a named detector, so a WRONG ownership verdict
// either double-counts (bridge fires on an owned key) or drops (bridge skips a
// key the named detector does not actually own), both recall/precision faults on
// the highest-volume generic path. Driven only through the public facade (which
// sorts+dedups via BTreeSet before the binary_search); no proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// EXACT MEMBERSHIP: `owned(keys, q)` must equal `keys.contains(q)` for ALL
    /// inputs, never a prefix/superstring/substring/case-fold match. The same
    /// small `[a-z_]` alphabet for both keys and query yields natural hits AND
    /// misses (and duplicate keys, which the BTreeSet dedups without changing
    /// membership), exercising both branches of the binary_search.
    #[test]
    fn owned_matches_naive_set_membership(
        keys in prop::collection::vec("[a-z_]{1,6}", 0..12),
        query in "[a-z_]{1,6}",
    ) {
        let key_refs: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
        let expected = keys.contains(&query);
        prop_assert_eq!(owned(&key_refs, &query), expected);
    }

    /// POSITIVE PATH: every key actually present in the set is owned, a stronger
    /// guarantee than the differential's incidental hits, catching a sort/dedup
    /// regression that could make the binary_search miss a genuine member.
    #[test]
    fn every_present_key_is_owned(
        keys in prop::collection::vec("[a-z_]{1,6}", 1..12),
        idx in 0usize..12,
    ) {
        let key_refs: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
        let chosen = &keys[idx % keys.len()];
        prop_assert!(
            owned(&key_refs, chosen),
            "present key {:?} was not owned",
            chosen
        );
    }
}
