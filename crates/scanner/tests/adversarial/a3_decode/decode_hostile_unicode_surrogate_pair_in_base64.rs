//! R5-T-SCAN decode hostile: surrogate-ish base64 no panic.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_unicode_surrogate_pair_in_base64() {
    let chunk = Chunk {
        data: "data=4pyT4p2k".into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "surrogate-ish base64 no panic; took {:?}",
        start.elapsed()
    );
}
