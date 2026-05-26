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
    fn empty_chunk_data_is_valid() {
        let source = StaticSource { text: "" };
        let chunk = source.chunks().next().unwrap().unwrap();
        assert!(chunk.data.is_empty());
    }
