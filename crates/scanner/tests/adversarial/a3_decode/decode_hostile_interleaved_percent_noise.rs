//! R5-REV-SCAN decode hostile: interleaved percent escapes must finish.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_interleaved_percent_noise() {
    let chunk = Chunk {
        data: "%41%42%43%".repeat(512).into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "interleaved percent noise finishes; took {:?}",
        start.elapsed()
    );
}
