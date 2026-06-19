//! R5-T-SCAN decode hostile: invalid utf8 percent no panic.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_invalid_utf8_percent() {
    let chunk = Chunk {
        data: "q=%FF%FE%41%4b%49%41".into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "invalid utf8 percent no panic; took {:?}",
        start.elapsed()
    );
}
