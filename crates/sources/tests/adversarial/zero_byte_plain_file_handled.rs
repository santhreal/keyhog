//! Zero-byte text files must not panic and must not emit bogus chunks.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn zero_byte_plain_file_handled() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("empty.txt"), b"").expect("write empty");
    std::fs::write(dir.path().join("marker.txt"), "MARKER=visible\n").expect("write marker");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "zero-byte plain file skip should not emit SourceError rows: {errors:?}"
    );

    assert!(
        chunks.iter().any(|c| c.data.contains("MARKER=visible")),
        "readable neighbor must still be scanned"
    );
    assert!(
        !chunks.iter().any(|c| c
            .metadata
            .path
            .as_deref()
            .is_some_and(|p| p.ends_with("empty.txt"))),
        "zero-byte file should be skipped, not surfaced as an empty chunk"
    );
}
