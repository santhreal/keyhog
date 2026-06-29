//! Gap test: the named-detector owner binary-search is an EXACT match.
//!
//! `generic_keyword_owner::normalized_assignment_keyword_owned_by_named_detector`
//! decides whether a normalized assignment key is already owned by a loaded
//! named detector, so the broad generic `KEY=value` bridge does not second-guess
//! it. It is a `binary_search` over a sorted, deduped `&[Arc<str>]` (the real
//! builder collects through a `BTreeSet`), so ownership is EXACT membership —
//! never a prefix, superstring, or substring, and case-sensitive.
//!
//! The helper had no direct coverage. The facade sorts/dedups the supplied
//! keywords through the same `BTreeSet`, so these vectors pass an intentionally
//! UNSORTED list and still resolve correctly — pinning both the exact-match
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
