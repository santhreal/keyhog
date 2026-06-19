use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn malformed_base64_candidates_do_not_panic() {
    let garbage = "=".repeat(10_000);
    let chunk = Chunk {
        data: garbage.into(),
        metadata: Default::default(),
    };
    let _ = decode_chunk(&chunk, 3, true, None, None);
}
