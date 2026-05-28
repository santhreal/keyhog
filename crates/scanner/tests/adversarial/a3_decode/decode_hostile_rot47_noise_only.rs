//! R5-T-SCAN decode hostile: rot47 noise only.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_rot47_noise_only() {
    let chunk = Chunk { data: "ROT47=~@\x7f".into(), metadata: Default::default() };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 5, true, None, None);
    assert!(start.elapsed() < Duration::from_secs(3));
}
