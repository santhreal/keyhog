//! Random bytes with .lz4 extension must not panic extraction.

use super::support::assert_compressed_error;
use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

#[test]
fn lz4_random_bytes_no_panic() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut buf = Vec::with_capacity(512);
    for i in 0u32..512 {
        buf.push((i.wrapping_mul(1103515245).wrapping_add(12345) >> 16) as u8);
    }
    std::fs::write(dir.path().join("noise.lz4"), &buf).expect("write");
    std::fs::write(
        dir.path().join("keep.txt"),
        "SECRET=visible
",
    )
    .expect("write");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains("visible")),
        "scan must survive malformed lz4"
    );
    assert_eq!(
        errors.len(),
        1,
        "random .lz4 bytes must emit one visible compressed-file error"
    );
    assert_compressed_error(errors[0]);
    assert_eq!(
        skip_counts().unreadable,
        1,
        "random .lz4 bytes must count one unreadable coverage gap"
    );
}
