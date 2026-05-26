//! Compressed file larger than max_file_size must be skipped entirely.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn oversize_compressed_input_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("big.gz"), vec![0u8; 8192]).expect("write");

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(1024);
    let count = source.chunks().flatten().count();
    assert_eq!(
        count, 0,
        "oversize compressed input must produce zero chunks"
    );
}
