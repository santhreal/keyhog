//! Decoded chunks inherit parent base_offset for location anchoring.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::decode_chunk;

#[test]
fn decoded_chunk_inherits_base_offset() {
    let text = r#"key = "c2stcHJvai1hYmMxMjM=""#;
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            base_offset: 4096,
            ..Default::default()
        },
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        decoded.iter().all(|c| c.metadata.base_offset == 4096),
        "every decoded chunk must inherit parent base_offset"
    );
}
