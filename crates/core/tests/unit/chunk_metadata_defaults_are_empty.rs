//! Migrated from `src/source.rs` inline tests.
use keyhog_core::ChunkMetadata;
#[test]
fn chunk_metadata_defaults_are_empty() {
    let metadata = ChunkMetadata::default();
    assert!(metadata.path.is_none());
    assert_eq!(metadata.base_offset, 0);
}
