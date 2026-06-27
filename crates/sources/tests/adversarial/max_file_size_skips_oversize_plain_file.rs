//! Files over max_file_size must be skipped visibly and bump SKIPPED_OVER_MAX_SIZE.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

#[test]
fn max_file_size_skips_oversize_plain_file() {
    // Aggregator-binary test: hold the exclusive scan scope across reset->scan->
    // read so a parallel test cannot reset `over_max_size` between this scan and
    // the assertion (which would zero the absolute count -> false failure).
    let _counter_guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("tiny.txt"),
        "ok
",
    )
    .expect("write");
    std::fs::write(dir.path().join("huge.txt"), vec![b'a'; 4096]).expect("write");

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(512);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].data.contains("ok"));
    assert_eq!(
        errors.len(),
        1,
        "oversize file must emit one visible SourceError"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("huge.txt")
            && error.contains("exceeds --max-file-size cap 512")
            && error.contains("file was not scanned"),
        "oversize SourceError must name the file and coverage gap, got {error}"
    );
    assert!(
        skip_counts().over_max_size >= 1,
        "oversize file must increment skip counter at least once"
    );
}
