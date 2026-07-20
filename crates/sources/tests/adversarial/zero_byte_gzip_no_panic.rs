//! Zero-byte `.gz` wrapper must fail loud while scan continues.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

#[test]
fn zero_byte_gzip_fails_loud_and_scan_continues() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("empty.gz"), []).expect("empty gz");
    std::fs::write(dir.path().join("side.txt"), "SIDE=ok\n").expect("side");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<String> = chunks.iter().map(|c| c.data.as_str().to_owned()).collect();
    assert!(bodies.iter().any(|b| b.contains("SIDE=ok")));
    assert_eq!(
        errors.len(),
        1,
        "zero-byte gzip must emit one visible source error"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("failed to scan compressed file")
            && err.contains("failed to decompress file")
            && err.contains("was not scanned"),
        "zero-byte gzip error should name the coverage gap, got {err}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "zero-byte gzip must count one unreadable coverage gap"
    );
}
