//! Migrated from `src/source.rs` inline tests.
use keyhog_core::{Chunk, ChunkMetadata};
#[test]
fn chunk_with_unicode_path_serializes_safely() {
    let chunk = Chunk {
        data: "TOKEN=abc".into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("src/日本語/keys.env".into()),
            ..Default::default()
        },
    };
    let json = serde_json::to_string(&chunk).unwrap();
    assert!(json.contains("日本語"));
    assert!(json.contains("TOKEN=abc"));
}
