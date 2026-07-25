//! Migrated from `src/source.rs` inline tests.
use keyhog_core::{Chunk, ChunkMetadata};
#[test]
fn chunk_with_unicode_path_fails_closed_without_serializing_source_text() {
    const SECRET: &str = "TOKEN=abc";
    let chunk = Chunk {
        data: SECRET.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("src/日本語/keys.env".into()),
            ..Default::default()
        },
    };
    let metadata_json =
        serde_json::to_string(&chunk.metadata).expect("non-sensitive metadata serializes");
    assert!(metadata_json.contains("日本語"));
    let mut output = Vec::new();
    let error = serde_json::to_writer(&mut output, &chunk)
        .expect_err("Chunk source text must refuse implicit serialization")
        .to_string();
    let partial = String::from_utf8_lossy(&output);
    assert!(!partial.contains("日本語"));
    assert!(!partial.contains(SECRET));
    assert!(error.contains("SensitiveString refuses implicit plaintext serialization"));
}
