//! Compressed file larger than max_file_size must be skipped entirely.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

#[test]
fn oversize_compressed_input_refused() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("big.gz"), vec![0u8; 8192]).expect("write");

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(1024);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert_eq!(
        chunks.len(),
        0,
        "oversize compressed input must produce zero chunks"
    );
    assert_eq!(
        errors.len(),
        1,
        "oversize compressed input must emit one visible SourceError"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("big.gz")
            && error.contains("exceeds --max-file-size cap 1024")
            && error.contains("file was not scanned"),
        "over-cap compressed SourceError must name the skipped file and cap, got {error}"
    );
    assert_eq!(
        skip_counts().over_max_size,
        1,
        "over-cap compressed input must increment over-max-size telemetry"
    );
}
