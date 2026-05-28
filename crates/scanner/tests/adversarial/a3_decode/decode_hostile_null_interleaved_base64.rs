//! R5-T-SCAN decode hostile: null in parent no panic.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_null_interleaved_base64() {
    let chunk = Chunk {
        data: "x=AKIA\\x00QYLPMN5HFIQR7XYA".into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "null in parent no panic; took {:?}",
        start.elapsed()
    );
}
