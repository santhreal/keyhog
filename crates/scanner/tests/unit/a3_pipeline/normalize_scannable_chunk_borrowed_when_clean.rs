use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::normalize_scannable_chunk;

#[test]
fn clean_ascii_chunk_borrowed() {
    let chunk = Chunk {
        data: "plain_ascii".into(),
        metadata: ChunkMetadata::default(),
    };
    let mut owned = None;
    let out = normalize_scannable_chunk(&chunk, &mut owned);
    assert_eq!(out.data.as_ref(), "plain_ascii");
    let _ = out;
    assert!(owned.is_none());
}
