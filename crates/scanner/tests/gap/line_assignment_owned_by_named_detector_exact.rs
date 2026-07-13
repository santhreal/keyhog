//! Gap test: the line-level named-detector owner check.
//!
//! `generic_keyword_owner::line_assignment_owned_by_named_detector` extracts the
//! assignment keyword a line is keying on (`assignment_keyword_for_line`, which
//! applies the credential-first right-to-left selection) and reports whether THAT
//! selected keyword is owned by a named detector. Contract: an empty owned set
//! owns nothing; a line whose selected keyword is owned is owned; a line whose
//! keyword is extracted but not owned (or no keyword at all) is not owned; and
//! the credential-first selection is threaded through, so a credential keyword
//! further left wins over a non-credential rightmost key.
//!
//! All vectors were traced through `assignment_keyword_for_line` and the sorted
//! `binary_search` membership check.

use keyhog_scanner::testing::line_assignment_owned_by_named_detector_for_test as line_owned;

#[test]
fn an_empty_owned_set_owns_nothing() {
    assert!(!line_owned(&[], "api_key=secret123"));
}

#[test]
fn a_line_whose_selected_keyword_is_owned_is_owned() {
    assert!(line_owned(&["api_key"], "api_key=secret123"));
}

#[test]
fn a_line_with_an_unowned_or_absent_keyword_is_not_owned() {
    // Keyword `other_key` is extracted but is not in the owned set.
    assert!(!line_owned(&["api_key"], "other_key=val"));
    // No `=`/`:` separator and no XML tag, so no keyword is extracted.
    assert!(!line_owned(&["api_key"], "just some text"));
}

#[test]
fn the_credential_first_selection_is_threaded_into_the_membership_check() {
    // The rightmost key `host` is not a credential, so the selection continues
    // left to the credential `api_key`, which is owned.
    assert!(line_owned(&["api_key"], "api_key=v host=h"));
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin empty/owned/unowned/credential-first; these SWEEP the
// exact COMPOSITION `line_assignment_owned` adds on top of the (separately tested)
// `assignment_keyword_for_line` extractor: empty set owns nothing, else the
// extracted keyword must be a MEMBER of the owned set. The oracle DELEGATES
// extraction to the real facade, so this is a true differential of the
// composition, and it cross-checks the source's sorted `binary_search` membership
// against a linear `any`, which agree ONLY if the facade sorts the owned set
// correctly. No proptest before.

use keyhog_scanner::testing::assignment_keyword_for_line_for_test as line_keyword;
use proptest::prelude::*;

/// Credential keys already in normalized form (extractor returns them unchanged
/// for a `key=value` line) (each must make its own line owned).
const OWNED_KEYS: &[&str] = &[
    "api_key",
    "client_secret",
    "access_token",
    "db_password",
    "user_pwd",
    "db_pass",
];

/// The composition oracle: empty set owns nothing; else the REAL extractor's
/// keyword must be a member of the owned set (linear `any`, cross-checking the
/// source's sorted `binary_search`).
fn oracle(owned: &[&str], line: &str) -> bool {
    if owned.is_empty() {
        return false;
    }
    line_keyword(line).is_some_and(|k| owned.iter().any(|o| *o == k.as_str()))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// FULL differential against the composition oracle over assignment-shaped
    /// lines and arbitrary owned sets.
    #[test]
    fn line_owned_matches_the_composition_oracle(
        line in r"[A-Za-z0-9_.:= -]{0,48}",
        owned in prop::collection::vec("[a-z_]{1,14}", 0..5),
    ) {
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        prop_assert_eq!(line_owned(&refs, &line), oracle(&refs, &line));
    }

    /// The same differential over ARBITRARY Unicode, locks that extraction +
    /// membership never panic and stay in agreement on non-ASCII input.
    #[test]
    fn line_owned_matches_oracle_on_arbitrary_unicode(
        line in "(?s).{0,48}",
        owned in prop::collection::vec("(?s).{0,14}", 0..5),
    ) {
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        prop_assert_eq!(line_owned(&refs, &line), oracle(&refs, &line));
    }

    /// RECALL: a line keyed on an owned credential keyword (`key=value`) is owned 
    /// pins the real extractor returns the key unchanged and membership hits.
    #[test]
    fn a_line_keyed_on_an_owned_credential_keyword_is_owned(
        i in 0usize..OWNED_KEYS.len(),
        value in "[A-Za-z0-9]{1,20}",
    ) {
        let key = OWNED_KEYS[i];
        let line = format!("{key}={value}");
        prop_assert!(line_owned(&[key], &line));
    }

    /// The empty owned set owns nothing, for any line.
    #[test]
    fn empty_owned_set_never_owns(line in "(?s).{0,48}") {
        prop_assert!(!line_owned(&[], &line));
    }

    /// Monotone in the owned set: adding owned keys can only ADD ownership.
    #[test]
    fn ownership_is_monotone_in_the_owned_set(
        line in r"[A-Za-z0-9_.:= -]{0,48}",
        owned in prop::collection::vec("[a-z_]{1,14}", 0..4),
        extra in prop::collection::vec("[a-z_]{1,14}", 0..3),
    ) {
        let base_refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        let base = line_owned(&base_refs, &line);
        let mut sup: Vec<&str> = base_refs.clone();
        sup.extend(extra.iter().map(|s| s.as_str()));
        prop_assert!(!base || line_owned(&sup, &line)); // base => sup
    }
}
