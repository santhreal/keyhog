//! R5-T-SCAN decode hostile: caesar on noise only.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_caesar_shift_noise_only() {
    let chunk = Chunk {
        data: "ROT13=NOPQRSTUVWXYZnopqrstuvwxyz".into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "caesar on noise only; took {:?}",
        start.elapsed()
    );
}
