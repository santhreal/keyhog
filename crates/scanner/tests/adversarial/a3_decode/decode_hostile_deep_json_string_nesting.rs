//! R5-T-SCAN decode hostile: deep json no stack blow.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_deep_json_string_nesting() {
    let chunk = Chunk {
        data: "{\"a\":{\"b\":{\"c\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}}}".into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "deep json no stack blow; took {:?}",
        start.elapsed()
    );
}
