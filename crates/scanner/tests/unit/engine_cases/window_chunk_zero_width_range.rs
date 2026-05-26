use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::engine::window_chunk;
#[test]
fn window_chunk_zero_width_range() {
    let parent = Chunk { data: "abc".into(), metadata: ChunkMetadata::default() };
    let slice = window_chunk(&parent, 1, 1);
    assert_eq!(slice.data.as_ref(), "");
}
