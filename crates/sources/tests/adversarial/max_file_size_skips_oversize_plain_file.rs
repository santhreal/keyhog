//! Files over max_file_size must be skipped and bump SKIPPED_OVER_MAX_SIZE.

use keyhog_core::Source;
use keyhog_sources::{reset_skipped_over_max_size, skip_counts, FilesystemSource};

#[test]
fn max_file_size_skips_oversize_plain_file() {
    reset_skipped_over_max_size();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("tiny.txt"),
        "ok
",
    )
    .expect("write");
    std::fs::write(dir.path().join("huge.txt"), vec![b'a'; 4096]).expect("write");

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(512);
    let chunks: Vec<_> = source.chunks().flatten().collect();
    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].data.contains("ok"));
    assert!(
        skip_counts().over_max_size >= 1,
        "oversize file must increment skip counter at least once"
    );
}
