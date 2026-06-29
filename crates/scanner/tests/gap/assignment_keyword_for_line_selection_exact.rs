//! Gap test: the per-line assignment-keyword selection.
//!
//! `entropy::keywords::assignment_keyword_for_line` decides which key a line is
//! assigning a value to. The selection contract:
//!   - an XML tag takes precedence and is returned directly (no credential gate);
//!   - otherwise the `=`/`:` separators are scanned RIGHT-TO-LEFT;
//!   - the first key that is a credential short-circuits and is returned, even if
//!     a separator further right held a non-credential key;
//!   - if no key is a credential, the rightmost non-credential key is the
//!     fallback;
//!   - a line with no separator (and no XML tag) yields None.
//!
//! All vectors were traced through `xml_assignment_tag`,
//! `normalize_assignment_keyword`, and `normalized_assignment_keyword_is_credential`.

use keyhog_scanner::testing::assignment_keyword_for_line_for_test as keyword_for_line;

#[test]
fn a_credential_key_before_a_separator_is_returned() {
    assert_eq!(
        keyword_for_line("api_key=AKIA1234"),
        Some("api_key".to_string())
    );
}

#[test]
fn the_first_credential_scanning_from_the_right_wins() {
    // Rightmost separator's key is already a credential.
    assert_eq!(
        keyword_for_line("user=bob password=hunter2"),
        Some("password".to_string())
    );
    // Rightmost key `host` is NOT a credential, so the scan continues left and
    // the credential `api_key` wins despite being further left.
    assert_eq!(
        keyword_for_line("api_key=AKIA host=localhost"),
        Some("api_key".to_string())
    );
}

#[test]
fn without_a_credential_the_rightmost_key_is_the_fallback() {
    // Neither `port` nor `host` is a credential; the rightmost (`port`) is kept.
    assert_eq!(
        keyword_for_line("host=localhost port=8080"),
        Some("port".to_string())
    );
}

#[test]
fn a_line_with_no_separator_has_no_assignment_keyword() {
    assert_eq!(keyword_for_line("just some text"), None);
}

#[test]
fn an_xml_tag_takes_precedence_over_an_inner_separator() {
    // The `<config>` tag is returned, not the `api_key` from the inner `=`.
    assert_eq!(
        keyword_for_line("<config>api_key=secret</config>"),
        Some("config".to_string())
    );
}
