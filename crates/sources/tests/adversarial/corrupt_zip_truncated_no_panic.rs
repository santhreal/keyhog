//! Truncated zip central directory must fail loud while scan continues.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

#[test]
fn corrupt_zip_truncated_fails_loud_and_scan_continues() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut bytes = b"PK\x03\x04".to_vec();
    bytes.extend_from_slice(&[0xDE; 128]);
    std::fs::write(dir.path().join("broken.zip"), bytes).expect("write");
    std::fs::write(dir.path().join("ok.txt"), "OK=1\n").expect("ok");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<String> = chunks.iter().map(|c| c.data.to_string()).collect();
    assert!(bodies.iter().any(|b| b.contains("OK=1")));
    assert_eq!(
        errors.len(),
        2,
        "corrupt ZIP must emit both duplicate-scan and parser coverage errors instead of looking clean; errors={errors:?}"
    );
    let duplicate_err = errors[0].to_string();
    assert!(
        duplicate_err.contains("ZIP duplicate-entry detection unavailable")
            && duplicate_err.contains("standard parser")
            && duplicate_err.contains("may miss duplicated or shadowed entries"),
        "ZIP duplicate-scan error should name the partial duplicate coverage gap, got {duplicate_err}"
    );
    let err = errors[1].to_string();
    assert!(
        err.contains("failed to scan ZIP archive")
            && err.contains("cannot read zip archive directory")
            && err.contains("was not scanned"),
        "ZIP error should name the unscanned archive coverage gap, got {err}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "corrupt ZIP directory failure must count one unreadable coverage gap"
    );
    assert_eq!(
        skip_counts().archive_duplicate_scan_unavailable,
        1,
        "corrupt ZIP duplicate-scan failure must count one duplicate-scan coverage gap"
    );
}
