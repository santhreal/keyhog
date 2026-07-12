//! Windowed-scan OOM-backstop ceiling (`engine/windowed.rs`), reached via the
//! `keyhog_scanner::testing` facade. Migrated from an inline `#[cfg(test)]`
//! block to satisfy the `engine_windowed_no_inline_tests` gate.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::{
    max_window_chunk_bytes, reject_oversized_window_chunk_for_test as reject,
};

#[test]
fn ceiling_is_four_gib() {
    // The windowed-scan hard skip is an absolute OOM backstop, NOT a routine
    // per-chunk gate: `scan_windowed` scans in bounded `MAX_SCAN_CHUNK_BYTES`
    // slices, so any chunk below this is fully covered. Pin the ceiling at 4 GiB
    // so it never regresses to the previous 512 MiB recall cliff that silently
    // dropped scannable multi-hundred-MiB chunks.
    assert_eq!(max_window_chunk_bytes(), 4 * 1024 * 1024 * 1024);
}

#[test]
fn normal_chunk_is_not_skipped() {
    let chunk = Chunk {
        data: "AKIAIOSFODNN7EXAMPLE token".to_string().into(),
        metadata: ChunkMetadata::default(),
    };
    assert!(!reject(&chunk, chunk.data.as_ref()));
}
