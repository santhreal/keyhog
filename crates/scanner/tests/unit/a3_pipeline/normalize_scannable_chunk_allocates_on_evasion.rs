use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::pipeline::normalize_scannable_chunk;

#[test]
fn evasion_char_forces_owned_chunk_allocation() {
    let chunk = Chunk {
        data: "key=\u{200b}val".into(),
        metadata: ChunkMetadata::default(),
    };
    let mut owned = None;
    let normalized = normalize_scannable_chunk(&chunk, &mut owned);
    assert!(!normalized.data.contains('\u{200b}'));
    assert_ne!(normalized.data.as_ref(), chunk.data.as_ref());
}
