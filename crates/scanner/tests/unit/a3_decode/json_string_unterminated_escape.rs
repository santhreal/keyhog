//! JSON decoder must handle unterminated escape sequences gracefully.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn json_escape_at_string_end() {
    // String ending with a backslash: `"value\"` (truncated escape).
    // The JSON extractor should skip this malformed string.
    let text = r#"{"key": "value\"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    // Should not produce a JSON decoder chunk (malformed string).
    assert!(
        !decoded
            .iter()
            .any(|c| c.metadata.source_type.contains("json")),
        "unterminated string with escape at end must be skipped"
    );
}

#[test]
fn json_unicode_escape_truncated() {
    // `\u00` with only 2 hex digits instead of 4.
    let text = r#"{"key": "pre\u00fix"}"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    // The JSON unescape must reject the invalid `\u` sequence and return Err.
    // As a result, no JSON decoded chunk should be emitted.
    assert!(
        !decoded
            .iter()
            .any(|c| c.metadata.source_type.contains("json")),
        "JSON with truncated \\uXX must not decode"
    );
}

#[test]
fn json_unicode_escape_at_string_end() {
    // `\u` at the end of the string with no hex digits following.
    let text = r#"{"key": "value\u"}"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    // Must not panic and must not emit a JSON chunk (malformed).
    assert!(
        !decoded
            .iter()
            .any(|c| c.metadata.source_type.contains("json")),
        "JSON string ending with \\u must be rejected"
    );
}

#[test]
fn json_valid_unicode_escape() {
    // Valid `\u0041` (= 'A').
    let text = r#"{"key": "pre\u0041fix"}"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    // Should produce a JSON decoded chunk with the unescaped character.
    assert!(
        decoded
            .iter()
            .any(|c| c.metadata.source_type.contains("json") && c.data.contains("preAfix")),
        "valid JSON \\uXXXX must decode to character: {decoded:?}"
    );
}

#[test]
fn json_escaped_quote_inside_string() {
    // `\"` is a valid escape for a literal quote inside a JSON string.
    let text = r#"{"key": "pre\"quote\"post"}"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    // Should decode successfully, converting `\"` to `"`.
    assert!(
        decoded
            .iter()
            .any(|c| c.metadata.source_type.contains("json")),
        "JSON with escaped quotes must decode"
    );
}

#[test]
fn json_backslash_at_end_of_string() {
    // String ending with `\\` (escaped backslash) is valid; with `\` alone is malformed.
    let text = r#"{"key": "value\\"}"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    // `\\` is valid JSON escape, should decode.
    assert!(
        decoded
            .iter()
            .any(|c| c.metadata.source_type.contains("json")),
        "JSON with escaped backslash must decode"
    );
}
