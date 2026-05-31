//! Caesar decoder must not run on source-code file paths.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::decode::decode_chunk;

#[test]
fn rust_source_comment_produces_no_caesar_chunks() {
    let chunk = Chunk {
        data: "//! Source trait and chunk types: pluggable input backends.".into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            source_type: "filesystem".into(),
            path: Some("crates/core/src/source.rs".into()),
            ..Default::default()
        },
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        decoded
            .iter()
            .all(|c| !c.metadata.source_type.contains("/caesar")),
        "Caesar decoder must not run on .rs source files; got {:?}",
        decoded
            .iter()
            .map(|c| &c.metadata.source_type)
            .collect::<Vec<_>>()
    );
}
