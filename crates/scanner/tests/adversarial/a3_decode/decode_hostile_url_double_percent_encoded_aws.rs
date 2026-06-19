//! R5-T-SCAN decode hostile: url percent run must not panic or hang.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn decode_hostile_url_double_percent_encoded_aws() {
    let chunk = Chunk {
        data: "percent=%25%32%46%41%4B%49%41%51%59%4c%50%4d%4e%35%48%46%49%51%52%37%58%59%41"
            .into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "url percent run must not panic or hang; took {:?}",
        start.elapsed()
    );
}
