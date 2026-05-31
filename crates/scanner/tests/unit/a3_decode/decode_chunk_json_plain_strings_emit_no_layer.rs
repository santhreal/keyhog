//! Plain JSON strings do not need a decode layer.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn json_plain_strings_emit_no_decoded_layer() {
    let chunk = Chunk {
        data: r#"{"name":"alpha","description":"ordinary json value"}"#.into(),
        metadata: Default::default(),
    };

    let decoded = decode_chunk(&chunk, 2, false, None, None);

    assert!(
        decoded
            .iter()
            .all(|c| !c.metadata.source_type.ends_with("/json")),
        "json decoder must not emit a duplicate layer for unescaped strings"
    );
}
