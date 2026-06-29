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
