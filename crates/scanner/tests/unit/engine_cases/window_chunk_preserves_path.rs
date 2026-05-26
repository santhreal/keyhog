use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::engine::window_chunk;
#[test]
fn window_chunk_preserves_path() {
    let mut meta = ChunkMetadata::default();
    meta.path = Some("src/main.rs".into());
    let parent = Chunk { data: "0123456789".into(), metadata: meta };
    let slice = window_chunk(&parent, 2, 6);
    assert_eq!(slice.data.as_ref(), "2345");
    assert_eq!(slice.metadata.path.as_deref(), Some("src/main.rs"));
}
