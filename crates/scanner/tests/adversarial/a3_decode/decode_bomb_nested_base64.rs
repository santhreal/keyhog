//! Deeply nested base64 must not hang - wall budget or depth cap stops work.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn nested_base64_decode_finishes_within_wall_budget() {
    let mut s = String::from("payload");
    for _ in 0..20 {
        s = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, s.as_bytes());
    }
    let chunk = Chunk {
        data: s.into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 10, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "decode bomb must finish quickly; took {:?}",
        start.elapsed()
    );
}
