//! R5-T decode hostile: hex with underscores bounded.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn r5t_decode_hostile_hex_with_underscores() {
    let chunk = Chunk {
        data: "h=6768705f414141414141414141414141414141414141414141414141".into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "hex with underscores bounded; took {:?}",
        start.elapsed()
    );
}
