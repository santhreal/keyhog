//! Gap test: `xml_assignment_tag` (entropy/keywords.rs).
//!
//! `xml_assignment_value` (covered by entropy_xml_close_tag_search.rs) ALWAYS
//! applies the credential-name filter, so it hides this function's distinct
//! behavior: returning the tag name for ANY well-formed open+matched-close
//! element (including non-credential `<title>`) and splitting the tag name off
//! attributes. Pin the open-tag acceptance, the close-tag match requirement, and
//! every rejection branch with exact `Option<String>` verdicts.

use keyhog_scanner::testing::xml_assignment_tag_for_test as xml_tag;

#[test]
fn non_credential_element_still_yields_its_tag_name() {
    // value-filter would return None here; the tag fn does not filter.
    assert_eq!(xml_tag("<title>hello</title>").as_deref(), Some("title"));
}

#[test]
fn tag_name_is_split_off_attributes() {
    assert_eq!(
        xml_tag("<password attr=\"x\">v</password>").as_deref(),
        Some("password")
    );
}

#[test]
fn close_comment_and_pi_markers_are_rejected() {
    assert_eq!(xml_tag("</password>"), None); // leading '/'
    assert_eq!(xml_tag("<!-- c -->"), None); // leading '!'
    assert_eq!(xml_tag("<?xml v?>"), None); // leading '?'
}

#[test]
fn missing_or_mismatched_close_tag_is_rejected() {
    assert_eq!(xml_tag("<password>v"), None); // no close tag at all
    assert_eq!(xml_tag("<password>v</token>"), None); // close name mismatch
}

#[test]
fn malformed_lines_are_rejected() {
    assert_eq!(xml_tag("plain text"), None); // no '<'
    assert_eq!(xml_tag("<   >x</>"), None); // empty/whitespace tag name
}
