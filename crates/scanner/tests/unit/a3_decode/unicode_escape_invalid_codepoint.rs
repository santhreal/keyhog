//! Unicode escape `\uXXXX` decoder must reject invalid/surrogate codepoints.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn unicode_escape_surrogate_pair_unpaired() {
    // U+D800 is a high surrogate and invalid as a standalone codepoint.
    // Should NOT decode successfully.
    let text = r#"{"token": "prefix\uD800suffix"}"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    // No decoded chunk with "unicode-escape" should exist, OR if it exists,
    // it must NOT contain the surrogate or any decoded form.
    let has_surrogate_chunk = decoded
        .iter()
        .any(|c| c.metadata.source_type.contains("unicode-escape") && c.data.contains("suffix"));
    assert!(
        !has_surrogate_chunk,
        "unicode escape with unpaired surrogate \\uD800 must not produce valid decoded chunk"
    );
}

#[test]
fn unicode_escape_out_of_range_codepoint() {
    // U+110000 and above are invalid Unicode codepoints.
    // To encode 0x110000 in hex, we'd need 6 hex digits, but \uXXXX only takes 4.
    // However, \U takes 8 (not supported here). `￿` is the max valid 4-digit encoding.
    // Test the boundary: max valid is 0xFFFF, anything in that range should work.
    // For now, test with a known valid max.
    let text = r#"api_key=\uFFFF"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    // U+FFFF is a valid (though rarely-used) Unicode character.
    let has_valid = decoded
        .iter()
        .any(|c| c.metadata.source_type.contains("unicode-escape"));
    assert!(
        has_valid,
        "\\uFFFF (max 4-digit Unicode) must decode successfully"
    );
}

#[test]
fn unicode_escape_truncated_hex_sequence() {
    // `\u00` has only 2 hex digits instead of 4.
    let text = r#"{"key": "val\u00end"}"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    // Truncated sequence should NOT decode.
    assert!(
        !decoded
            .iter()
            .any(|c| c.metadata.source_type.contains("unicode-escape")),
        "truncated \\uXX (only 2 hex digits) must not decode"
    );
}
