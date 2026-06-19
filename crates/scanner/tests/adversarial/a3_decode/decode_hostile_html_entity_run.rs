//! R5-T-SCAN decode hostile: HTML entity run bounded.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_html_entity_run() {
    let chunk = Chunk {
        data: "&#65;&#75;&#73;&#65;".repeat(100).into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 5, true, None, None);
    assert!(start.elapsed() < Duration::from_secs(3));
}
