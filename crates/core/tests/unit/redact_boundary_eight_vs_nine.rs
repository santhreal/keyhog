//! Proving test: redact contract at 8-char boundary.
//! Credentials <= 8 chars (ASCII or UTF-8) must redact to exactly "****".
//! Credentials >= 9 chars reveal only a length-scaled edge window.

use keyhog_core::redact;

#[test]
fn redact_exactly_eight_ascii_chars_returns_stars_not_preview() {
    // Boundary: 8 chars (inclusive) must NOT reveal any character.
    assert_eq!(redact("abcdefgh"), "****");
    assert_eq!(redact("ABCDEFGH"), "****");
    assert_eq!(redact("12345678"), "****");
}

#[test]
fn redact_exactly_nine_ascii_chars_reveals_edges_not_middle() {
    // Boundary: 9 chars reveals one char from each edge.
    let result = redact("abcdefghi");
    assert_eq!(result, "a...i");
    assert_eq!(result.len(), 5, "format is 'first1...last1'");
}

#[test]
fn redact_eight_utf8_graphemes_returns_stars() {
    // UTF-8 boundary: 8 graphemes → "****"
    // "αβγδεζηθ" = 8 Greek characters
    assert_eq!(redact("αβγδεζηθ"), "****");
}

#[test]
fn redact_nine_utf8_graphemes_reveals_edges() {
    // UTF-8 boundary: 9 graphemes -> first 1 + "..." + last 1.
    let result = redact("αβγδεζηθι");
    assert!(result.starts_with('α'), "first grapheme must be preserved");
    assert!(result.ends_with('ι'), "last grapheme must be preserved");
    assert!(
        result.contains("..."),
        "ellipsis must separate first and last"
    );
}

#[test]
fn redact_cjk_multibyte_eight_graphemes_is_fully_masked() {
    // Each CJK character is 3+ bytes but counts as 1 grapheme.
    // "一二三四五六七八" = 8 CJK graphemes, all multibyte.
    assert_eq!(redact("一二三四五六七八"), "****");
}

#[test]
fn redact_cjk_multibyte_nine_graphemes_preserves_edges() {
    // "一二三四五六七八九" = 9 CJK graphemes.
    let result = redact("一二三四五六七八九");
    assert!(result.starts_with('一'));
    assert!(result.ends_with('九'));
    assert!(result.contains("..."));
}
