use keyhog_scanner::engine::coalesce_chunks;
use keyhog_core::Chunk;
#[test]
fn coalesce_chunk_count_preserved_04() {
    let n = 4;
    let chunks: Vec<Chunk> = (0..n).map(|j| Chunk::from(format!("c{j}"))).collect();
    let (entries, _) = coalesce_chunks(&chunks);
    assert_eq!(entries.len(), n);
}
