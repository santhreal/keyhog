//! R5-T archive adversarial: truncated gzip member fails loud.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

#[test]
fn r5t_gzip_truncated_member_fails_loud() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("trunc.gz"), &[0x1f, 0x8b, 0x08, 0x00]).expect("write");
    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (_chunks, errors) = split_chunk_results(&rows);
    assert_eq!(
        errors.len(),
        1,
        "truncated gzip must emit one visible source error"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("failed to scan compressed file")
            && err.contains("failed to decompress file")
            && err.contains("was not scanned"),
        "truncated gzip error should name the coverage gap, got {err}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "truncated gzip header must count one unreadable coverage gap"
    );
}
