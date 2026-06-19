//! LR1-A8 replacement gate: `decode/unicode_escape.rs` hex escapes decode to sk.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::decode_chunk;

#[test]
fn unicode_escape_hex_sequence_decodes_sk_prefix() {
    let chunk = Chunk {
        data: r#"\x73\x6b"#.into(),
        metadata: ChunkMetadata::default(),
    };
    let layers = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        layers.iter().any(|c| c.data.contains("sk")),
        "unicode hex escapes must decode to 'sk' in at least one layer"
    );
}
