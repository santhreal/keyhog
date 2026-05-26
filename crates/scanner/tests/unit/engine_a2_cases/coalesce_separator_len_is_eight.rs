use keyhog_core::Chunk;
use keyhog_scanner::engine::coalesce_chunks;
#[test]
fn coalesce_separator_len_is_eight() {
    let chunks = vec![Chunk::from("ab"), Chunk::from("cd")];
    let (_, buf) = coalesce_chunks(&chunks);
    assert_eq!(buf.len(), 2 + 8 + 2);
}
