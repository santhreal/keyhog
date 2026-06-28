//! xml_assignment_value extracts the inner text of a credential-named XML element
//! using a zero-alloc close-tag search instead of building `format!("</{tag}>")`
//! (twice, across xml_assignment_tag + xml_assignment_value) per XML-shaped line
//! (Law 7 + DEDUP). This pins the equivalence to the old formatted-needle form:
//! the same open/close span is located and the inner text is returned trimmed.

use keyhog_scanner::testing::entropy_keywords::xml_assignment_value;

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
