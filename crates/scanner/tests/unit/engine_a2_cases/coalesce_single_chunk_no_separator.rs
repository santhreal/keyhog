use keyhog_core::Chunk;
use keyhog_scanner::engine::coalesce_chunks;
#[test]
fn coalesce_single_chunk_no_separator() {
    let (_, buf) = coalesce_chunks(&[Chunk::from("only")]);
    assert_eq!(buf, b"only");
}
