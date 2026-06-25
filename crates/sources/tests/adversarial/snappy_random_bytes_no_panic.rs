//! Random bytes with .sz extension must not panic extraction.

use super::support::assert_compressed_error;
use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

#[test]
fn snappy_random_bytes_no_panic() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("bad.sz"), vec![0xFFu8; 128]).expect("write");
    std::fs::write(
        dir.path().join("fine.cfg"),
        "KEY=ok
",
    )
    .expect("write");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains("KEY=ok")),
        "valid neighbor file must still scan; chunks={chunks:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "random .sz bytes must emit one visible compressed-file error"
    );
    assert_compressed_error(errors[0]);
    assert_eq!(
        skip_counts().unreadable,
        1,
        "random .sz bytes must count one unreadable coverage gap"
    );
}
