//! Non-text binary files must fall back to printable-string extraction.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn filesystem_binary_strings_fallback() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("blob.dat"),
        b"\x00\x01\x02HARDCODED_KEY=AKIAINTEGRATIONFALLBACK00\x00\xFF",
    )
    .expect("write");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid binary-string fallback fixture must not emit SourceError rows, got {errors:?}"
    );
    assert!(
        chunks.iter().any(|c| {
            c.metadata.source_type == "filesystem:binary-strings"
                && c.data.contains("AKIAINTEGRATIONFALLBACK00")
        }),
        "binary fallback must emit printable strings; got {chunks:?}"
    );
}
