//! Invalid JSON `\u` escapes must not produce decoded chunks.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

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
