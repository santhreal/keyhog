//! R5-T-SCAN decode hostile: hex blob decode finishes.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_hex_encoded_github_pat_fragment() {
    let chunk = Chunk {
        data: "hex=6768705f414141414141414141414141414141414141414141414141".into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "hex blob decode finishes; took {:?}",
        start.elapsed()
    );
}
