//! R5-T decode hostile: triple url encoding bounded.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn r5t_decode_hostile_triple_url_encoding() {
    let chunk = Chunk {
        data: "q=%2541%254b%2549%2541".into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "triple url encoding bounded; took {:?}",
        start.elapsed()
    );
}
