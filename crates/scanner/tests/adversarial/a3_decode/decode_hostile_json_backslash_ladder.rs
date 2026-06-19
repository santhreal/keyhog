//! R5-REV-SCAN decode hostile: nested JSON string escapes must finish.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_json_backslash_ladder() {
    let body = format!(r#"{{"a":"{}"}}"#, "\\".repeat(256));
    let chunk = Chunk {
        data: body.into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "json backslash ladder finishes; took {:?}",
        start.elapsed()
    );
}
