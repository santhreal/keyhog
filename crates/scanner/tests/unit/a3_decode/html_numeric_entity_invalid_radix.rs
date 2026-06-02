//! HTML numeric entity decoder must reject invalid radix usage and out-of-range codepoints.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn html_numeric_entity_decimal_overflow() {
    // `&#99999999;` is a valid decimal syntax but the codepoint is out of range for `char`.
    let text = r#"<p>&#99999999;</p>"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    // Should NOT produce an html-numeric-entity chunk; the decode fails gracefully.
    assert!(
        !decoded.iter().any(|c| c.metadata.source_type.contains("html-numeric-entity")),
        "invalid codepoint &#99999999 must be rejected"
    );
}

#[test]
fn html_numeric_entity_hex_incomplete() {
    // `&#x;` has no hex digits.
    let text = r#"text&#x;more"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    assert!(
        !decoded.iter().any(|c| c.metadata.source_type.contains("html-numeric-entity")),
        "&#x; (no hex digits) must not decode"
    );
}

#[test]
fn html_numeric_entity_hex_valid() {
    // `&#x41;` is valid hex encoding of 'A'.
    let text = r#"<p>&#x41;</p>"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    assert!(
        decoded.iter().any(|c| c.metadata.source_type.contains("html-numeric-entity")),
        "valid &#xNN entity must decode"
    );
}

#[test]
fn html_numeric_entity_decimal_valid() {
    // `&#65;` is decimal 'A'.
    let text = r#"<p>&#65;</p>"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    assert!(
        decoded.iter().any(|c| c.metadata.source_type.contains("html-numeric-entity") && c.data.contains("A")),
        "valid &#DDD entity must decode to character"
    );
}

#[test]
fn html_numeric_entity_malformed_no_terminator() {
    // `&#65` without closing `;` may not parse (depends on implementation).
    let text = r#"<p>&#65</p>"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    // Impl may either skip it or emit unterminated content. Either is OK; just ensure no panic.
    let _ = decoded;
}
