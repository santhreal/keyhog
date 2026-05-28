//! R5-T decode hostile: json unicode escape run bounded.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn r5t_decode_hostile_json_unicode_escape_run() {
    let chunk = Chunk {
        data: "{\"u\":\"\\\\u0041\\\\u0042\\\\u0043\\\\u0044\\\\u0045\"}".into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "json unicode escape run bounded; took {:?}",
        start.elapsed()
    );
}
