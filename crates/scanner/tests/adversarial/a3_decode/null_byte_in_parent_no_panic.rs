use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn embedded_nul_in_parent_chunk_no_panic() {
    let mut data = String::from("key=c2stcHJvai1hYmMxMjM=");
    data.push('\0');
    data.push_str("tail");
    let chunk = Chunk {
        data: data.into(),
        metadata: Default::default(),
    };
    let _ = decode_chunk(&chunk, 2, true, None, None);
}
