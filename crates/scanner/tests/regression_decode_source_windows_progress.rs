//! Regression and property tests for decode window advancement and progress bounds (Row 67).
//!
//! WHY: In a release build (`debug-assertions = false`), an out-of-range overlap calculation
//! combined with UTF-8 boundary backoff previously caused `decode_source_windows` to fail
//! to advance (`start = next = start`), creating an infinite loop that allocated matches
//! without bound. This suite verifies strict window advancement, termination under deadline,
//! and complete coverage across multi-byte UTF-8 scalar boundaries.
//! What it does not catch: memory allocation exhaustion outside the decode loop.

#![cfg(feature = "decode")]

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::decode_source_windows_for_test;
use std::time::{Duration, Instant};

#[test]
fn decode_source_windows_one_byte_followed_by_four_byte_scalar_terminates() {
    let text = "a\u{10000}";
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("test.txt".into()),
            base_offset: 0,
            base_line: 1,
            ..Default::default()
        },
    };

    let start_time = Instant::now();
    let mut visited = Vec::new();
    decode_source_windows_for_test(4, &chunk, 2, |window| {
        visited.push(window.data.to_string());
        assert!(
            start_time.elapsed() < Duration::from_secs(2),
            "decode_source_windows exceeded deadline (infinite loop)"
        );
        Ok(())
    })
    .expect("decode_source_windows should succeed");

    assert!(!visited.is_empty(), "must visit at least one window");
    assert!(
        start_time.elapsed() < Duration::from_secs(2),
        "execution took too long"
    );
}

#[test]
fn decode_source_windows_four_ascii_followed_by_three_byte_scalar_terminates() {
    let text = "abcd\u{20ac}";
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("test.txt".into()),
            base_offset: 0,
            base_line: 1,
            ..Default::default()
        },
    };

    let start_time = Instant::now();
    let mut visited = Vec::new();
    decode_source_windows_for_test(4, &chunk, 2, |window| {
        visited.push(window.data.to_string());
        assert!(
            start_time.elapsed() < Duration::from_secs(2),
            "decode_source_windows exceeded deadline (infinite loop)"
        );
        Ok(())
    })
    .expect("decode_source_windows should succeed");

    assert!(!visited.is_empty(), "must visit at least one window");
}

#[test]
fn decode_source_windows_sweeps_multibyte_scalars_and_strictly_advances() {
    // Test across multi-byte UTF-8 characters at various offsets with small limits
    let test_scalars = ["a", "\u{e9}", "\u{20ac}", "\u{10000}"]; // 1, 2, 3, 4 bytes
    for limit in 4..=32 {
        for prefix_len in 0..=8 {
            for scalar in &test_scalars {
                for suffix_len in 0..=8 {
                    let mut text = "x".repeat(prefix_len);
                    text.push_str(scalar);
                    text.push_str(&"y".repeat(suffix_len));

                    let chunk = Chunk {
                        data: text.clone().into(),
                        metadata: ChunkMetadata {
                            source_type: "test".into(),
                            path: Some("test.txt".into()),
                            base_offset: 0,
                            base_line: 1,
                            ..Default::default()
                        },
                    };

                    let start_time = Instant::now();
                    let mut prev_offset = None;
                    let mut visited_bytes = 0usize;

                    decode_source_windows_for_test(limit, &chunk, limit / 2, |window| {
                        let cur_offset = window.metadata.base_offset;
                        if let Some(prev) = prev_offset {
                            assert!(
                                cur_offset > prev,
                                "window base offset must strictly advance: cur={cur_offset}, prev={prev}, limit={limit}, text={text:?}"
                            );
                        }
                        prev_offset = Some(cur_offset);
                        visited_bytes += window.data.len();
                        assert!(
                            start_time.elapsed() < Duration::from_secs(2),
                            "execution exceeded 2s deadline for limit={limit}, text={text:?}"
                        );
                        Ok(())
                    })
                    .expect("decode_source_windows should succeed");

                    assert!(
                        visited_bytes >= text.len() || text.is_empty(),
                        "visited windows must cover input text"
                    );
                }
            }
        }
    }
}
