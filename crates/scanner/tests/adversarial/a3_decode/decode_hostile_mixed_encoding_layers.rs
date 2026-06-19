//! R5-T-SCAN decode hostile: mixed layers finish quickly.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_mixed_encoding_layers() {
    let chunk = Chunk {
        data: "a=b64:QUtJQVFMUE1ONUhGSVFSN1hZQQ==&u=%41%4b%49%41".into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "mixed layers finish quickly; took {:?}",
        start.elapsed()
    );
}
