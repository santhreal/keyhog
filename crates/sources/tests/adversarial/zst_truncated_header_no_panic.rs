//! Truncated zstd payload must not panic the filesystem iterator.

use super::support::assert_compressed_error;
use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

#[test]
fn zst_truncated_header_no_panic() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("broken.zst"),
        [0x28, 0xb5, 0x2f, 0xfd, 0x00],
    )
    .expect("write");
    std::fs::write(
        dir.path().join("ok.env"),
        "TOKEN=still-here
",
    )
    .expect("write");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<String> = chunks.iter().map(|c| c.data.as_str().to_owned()).collect();
    assert!(
        bodies.iter().any(|b| b.contains("still-here")),
        "valid neighbor file must still scan; got {bodies:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "truncated zstd must emit one visible compressed-file error"
    );
    assert_compressed_error(errors[0]);
    assert_eq!(
        skip_counts().unreadable,
        1,
        "truncated zstd must count one unreadable coverage gap"
    );
}
