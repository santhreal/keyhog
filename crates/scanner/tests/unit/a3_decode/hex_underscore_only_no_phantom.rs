//! Underscore-only quoted blobs must not decode as hex.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn underscore_only_string_produces_no_hex_decoded_chunks() {
    let chunk = Chunk {
        data: "\"_____________________________\"".into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        decoded
            .iter()
            .all(|c| !c.metadata.source_type.contains("/hex")),
        "underscore-only literal must not emit hex-decoded chunks"
    );
}
