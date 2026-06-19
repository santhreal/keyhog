//! Empty chunk produces no decoded outputs.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn empty_chunk_yields_empty_decode_list() {
    let chunk = Chunk {
        data: String::new().into(),
        metadata: Default::default(),
    };
    assert!(decode_chunk(&chunk, 3, true, None, None).is_empty());
}
