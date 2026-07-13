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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example per branch; these SWEEP them. CONSTRUCTIVE
// positives (a well-formed `<tag>…</tag>`, with and without attributes, yields the
// tag name) and negatives (no `<`; a `/`/`!`/`?` marker after `<`; a missing or
// mismatched close), plus a UNIVERSAL invariant: any admitted tag is non-empty,
// never starts with `/`, and the line genuinely contains a matching `</tag>`.
// Traced against parse_xml_assignment + find_xml_close_tag. No proptest before.

use proptest::prelude::*;

const MARKERS: &[char] = &['/', '!', '?'];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// RECALL: a well-formed element yields its tag name, including a
    /// non-credential tag and one carrying attributes (name split off attributes).
    #[test]
    fn well_formed_element_yields_its_tag_name(
        t in "[a-z][a-z0-9]{0,8}",
        v in "[a-zA-Z0-9 ]{0,10}",
        attr in "[a-z]{1,5}=\"[a-z]{1,5}\"",
        with_attr in any::<bool>(),
    ) {
        let line = if with_attr {
            format!("<{t} {attr}>{v}</{t}>")
        } else {
            format!("<{t}>{v}</{t}>")
        };
        let got = xml_tag(&line);
        prop_assert_eq!(got.as_deref(), Some(t.as_str()));
    }

    /// A line with no `<` has no XML tag.
    #[test]
    fn a_line_without_an_open_bracket_is_rejected(line in "[a-zA-Z0-9 /!?=]{0,24}") {
        prop_assert!(xml_tag(&line).is_none());
    }

    /// A `/`/`!`/`?` immediately after `<` (close tag, comment, processing
    /// instruction) is rejected.
    #[test]
    fn markers_after_the_open_bracket_are_rejected(
        m in 0usize..MARKERS.len(),
        rest in "[a-z ]{0,10}",
    ) {
        let line = format!("<{}{rest}>x</x>", MARKERS[m]);
        prop_assert!(xml_tag(&line).is_none());
    }

    /// A missing close, or a close whose name does not match the open tag, is
    /// rejected (the value alphabet excludes `<`, so no stray close appears).
    #[test]
    fn missing_or_mismatched_close_is_rejected(
        t in "[a-z][a-z0-9]{0,6}",
        other in "[a-z][a-z0-9]{0,6}",
        v in "[a-z]{0,8}",
    ) {
        prop_assume!(t != other);
        let missing = format!("<{t}>{v}");
        let mismatched = format!("<{t}>{v}</{other}>");
        prop_assert!(xml_tag(&missing).is_none());
        prop_assert!(xml_tag(&mismatched).is_none());
    }

    /// UNIVERSAL: any admitted tag is non-empty, never starts with `/`, and the
    /// line genuinely contains the matching `</tag>` close. Also no panic on
    /// XML-ish input.
    #[test]
    fn an_admitted_tag_has_a_matching_close(line in "[a-zA-Z0-9<>/!?= \"]{0,30}") {
        if let Some(tag) = xml_tag(&line) {
            prop_assert!(!tag.is_empty());
            prop_assert!(!tag.starts_with('/'));
            let close = format!("</{tag}>");
            prop_assert!(line.contains(&close), "no matching close {:?} in {:?}", close, line);
        }
    }

    /// Never panics on arbitrary Unicode.
    #[test]
    fn never_panics_on_arbitrary_input(line in "(?s).{0,40}") {
        let _ = xml_tag(&line);
    }
}
