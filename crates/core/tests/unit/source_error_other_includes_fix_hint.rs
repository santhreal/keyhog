//! Migrated from `src/source.rs` inline tests.
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
struct StaticSource {
    text: &'static str,
}
impl Source for StaticSource {
    fn name(&self) -> &str {
        "static"
    }
    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        Box::new(std::iter::once(Ok(Chunk {
            data: self.text.into(),
            metadata: ChunkMetadata {
                source_type: "static".into(),
                ..Default::default()
            },
        })))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
#[test]
fn source_error_other_includes_fix_hint() {
    let err = SourceError::Other("missing path".into());
    assert!(err.to_string().contains("Fix:"));
}
