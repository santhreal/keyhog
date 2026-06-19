//! R5-REV-SCAN decode hostile: base85-ish run must finish under budget.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_long_base64_padding_run() {
    let chunk = Chunk {
        data: format!("data={}", "A".repeat(8192)).into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "long base64 padding run finishes; took {:?}",
        start.elapsed()
    );
}
