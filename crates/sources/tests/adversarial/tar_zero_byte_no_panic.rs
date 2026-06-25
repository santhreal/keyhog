//! Zero-byte tar file must not panic archive dispatch.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn tar_zero_byte_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("empty.tar"), []).expect("empty tar");
    std::fs::write(dir.path().join("ok.txt"), "OK=1\n").expect("ok");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid zero-byte tar should not emit SourceError rows: {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "zero-byte tar should emit no archive chunks while side file survives: {chunks:?}"
    );
    assert!(
        chunks[0].data.contains("OK=1"),
        "side file must still scan when a zero-byte tar is present: {chunks:?}"
    );
    assert!(
        chunks[0]
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with("ok.txt")),
        "side chunk path must identify the scanned sibling, got {chunks:?}"
    );
}
