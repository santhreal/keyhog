//! Migrated from `src/source.rs` inline tests.
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
struct StaticSource { text: &'static str }
impl Source for StaticSource {
    fn name(&self) -> &str { "static" }
    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        Box::new(std::iter::once(Ok(Chunk {
            data: self.text.into(),
            metadata: ChunkMetadata { source_type: "static".into(), ..Default::default() },
        })))
    }
    fn as_any(&self) -> &dyn std::any::Any { self }
}
#[test]
    fn chunk_metadata_defaults_are_empty() {
        let metadata = ChunkMetadata::default();
        assert!(metadata.path.is_none());
        assert_eq!(metadata.base_offset, 0);
    }
