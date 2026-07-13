//! xml_assignment_value extracts the inner text of a credential-named XML element
//! using a zero-alloc close-tag search instead of building `format!("</{tag}>")`
//! (twice, across xml_assignment_tag + xml_assignment_value) per XML-shaped line
//! (Law 7 + DEDUP). This pins the equivalence to the old formatted-needle form:
//! the same open/close span is located and the inner text is returned trimmed.

use keyhog_scanner::testing::entropy_keywords::xml_assignment_value;
use keyhog_scanner::testing::normalized_assignment_keyword_is_credential_for_test as is_cred;

#[test]
fn xml_close_tag_search_matches_formatted_needle() {
    // Canonical credential-named element: inner text returned verbatim.
    assert_eq!(
        xml_assignment_value("<password>secret_val_123</password>").as_deref(),
        Some("secret_val_123")
    );
    // Interior whitespace is trimmed (matches the old `.trim()` on the span).
    assert_eq!(
        xml_assignment_value("<token>  abc_def_ghi  </token>").as_deref(),
        Some("abc_def_ghi")
    );
    // Leading indentation before the element is tolerated (line is trimmed first).
    assert_eq!(
        xml_assignment_value("    <secret>xyz789value</secret>").as_deref(),
        Some("xyz789value")
    );

    // A non-credential tag name -> None even though the element is well-formed.
    assert_eq!(xml_assignment_value("<title>hello world</title>"), None);
    // Open tag with no matching close -> None (search returns None).
    assert_eq!(xml_assignment_value("<password>secret"), None);
    // Mismatched close tag (`</token>` for a `<password>` open) -> None: the
    // close-tag search requires the exact name bytes, so `</password>` is absent.
    assert_eq!(xml_assignment_value("<password>x</token>"), None);
    // A stray earlier `<` that is not `</name>` must be skipped, then the real
    // close found (the search advances past non-`</tag>` `<` positions).
    assert_eq!(
        xml_assignment_value("<password>a<b>c</password>").as_deref(),
        Some("a<b>c")
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vector pins a handful of shapes; these SWEEP the contract.
// `xml_assignment_value` = parse `<tag>value</tag>` → `normalize_assignment_keyword`
// → gate on `normalized_assignment_keyword_is_credential`. The FIRST property is a
// cross-facade DIFFERENTIAL: for any well-formed element with a clean identifier
// tag (normalize is identity), the value is returned iff the tag is credential
// decided by the tested `is_cred` facade, so it covers positive AND negative, and
// both the `_`-suffix path and the compact path, without hardcoding the tag set.
// The other three pin the close-tag search: no close → None, mismatched close →
// None, and an interior `<...>` that is not the close tag stays part of the value.
// Traced against keywords.rs:589. No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// A well-formed element returns its (trimmed) inner value iff the tag is a
    /// credential keyword, the value is gated by `is_cred(normalize(tag))`. Clean
    /// identifier tags (letters, single underscores) make normalize the identity,
    /// so `is_cred(tag)` is the exact oracle. Leading indentation is tolerated.
    #[test]
    fn credential_tag_gates_the_value(
        indent in "[ \t]{0,4}",
        tag in "[a-z]{2,6}(_[a-z]{2,6}){0,2}",
        value in "[a-zA-Z0-9_.-]{1,20}",
    ) {
        let line = format!("{indent}<{tag}>{value}</{tag}>");
        let got = xml_assignment_value(&line);
        let expected = if is_cred(&tag) { Some(value.as_str()) } else { None };
        prop_assert_eq!(got.as_deref(), expected);
    }

    /// An open credential tag with no matching close yields None.
    #[test]
    fn missing_close_tag_is_none(value in "[a-zA-Z0-9_.-]{1,20}") {
        let line = format!("<password>{value}");
        prop_assert!(xml_assignment_value(&line).is_none());
    }

    /// A mismatched close tag (`</token>` closing a `<password>`) yields None, the
    /// close-tag search requires the exact name bytes.
    #[test]
    fn mismatched_close_tag_is_none(value in "[a-zA-Z0-9_.-]{1,20}") {
        let line = format!("<password>{value}</token>");
        prop_assert!(xml_assignment_value(&line).is_none());
    }

    /// An interior `<...>` that is not the close tag stays part of the value (the
    /// search advances past non-`</password>` `<` positions).
    #[test]
    fn interior_angle_bracket_is_part_of_value(
        a in "[a-zA-Z0-9]{1,6}",
        b in "[a-zA-Z]{1,4}",
        c in "[a-zA-Z0-9]{0,6}",
    ) {
        let line = format!("<password>{a}<{b}>{c}</password>");
        let got = xml_assignment_value(&line);
        let expected = format!("{a}<{b}>{c}");
        prop_assert_eq!(got.as_deref(), Some(expected.as_str()));
    }
}
