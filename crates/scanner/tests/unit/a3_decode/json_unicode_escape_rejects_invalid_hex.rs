//! Invalid JSON `\u` escapes must not produce decoded chunks.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn json_unicode_escape_rejects_invalid_hex() {
    let text = r#"{"token": "bad\uZZZZ"}"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        decoded
            .iter()
            .all(|c| !c.metadata.source_type.contains("/json")),
        "invalid \\u hex must not emit json-decoded chunks"
    );
}

#[test]
fn json_unicode_escape_rejects_unpaired_high_surrogate() {
    let text = r#"{"token": "\uD83DAKIAIOSFODNN7EXAMPLE"}"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        decoded
            .iter()
            .all(|c| !c.metadata.source_type.contains("/json")),
        "unpaired JSON high surrogate must not emit a partially decoded credential"
    );
}

#[test]
fn json_unicode_escape_rejects_unpaired_low_surrogate() {
    let text = r#"{"token": "\uDE00AKIAIOSFODNN7EXAMPLE"}"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        decoded
            .iter()
            .all(|c| !c.metadata.source_type.contains("/json")),
        "unpaired JSON low surrogate must not emit a partially decoded credential"
    );
}
