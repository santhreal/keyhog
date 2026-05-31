use keyhog_core::Source;
use keyhog_sources::{reader_pool_thread_count_for_test, FilesystemSource};
use std::path::PathBuf;

#[test]
fn filesystem_source_yields_file_contents() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("secret.env");
    std::fs::write(&file, "TOKEN=abc123\n").unwrap();

    let source = FilesystemSource::new(PathBuf::from(dir.path()));
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert!(!chunks.is_empty());
    assert!(chunks[0].data.contains("TOKEN=abc123"));
}

#[test]
fn filesystem_source_missing_path_yields_nothing() {
    let source = FilesystemSource::new(PathBuf::from("/tmp/keyhog-missing-path-xyzzy-999"));
    assert!(source.chunks().next().is_none());
}

#[test]
fn filesystem_reader_pool_is_smaller_than_scan_pool_on_large_hosts() {
    assert_eq!(reader_pool_thread_count_for_test(1), 2);
    assert_eq!(reader_pool_thread_count_for_test(4), 2);
    assert_eq!(reader_pool_thread_count_for_test(32), 16);
    assert_eq!(reader_pool_thread_count_for_test(64), 16);
}
