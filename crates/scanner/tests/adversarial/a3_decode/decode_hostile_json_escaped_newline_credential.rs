//! R5-T-SCAN decode hostile: json escape decode no panic.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_json_escaped_newline_credential() {
    let chunk = Chunk {
        data: "{\"k\":\"c2st\\\\nliXZV9hYmMxMjM=\"}".into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "json escape decode no panic; took {:?}",
        start.elapsed()
    );
}
