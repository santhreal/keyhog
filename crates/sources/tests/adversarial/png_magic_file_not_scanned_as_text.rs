//! PNG magic header must be rejected by text decode path.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn png_magic_file_not_scanned_as_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.extend_from_slice(b"SECRET=hidden");
    std::fs::write(dir.path().join("img.dat"), bytes).expect("write");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "PNG magic binary-string recovery should not emit SourceError rows: {errors:?}"
    );
    assert!(
        chunks
            .iter()
            .all(|chunk| chunk.metadata.source_type.as_ref() != "filesystem"),
        "PNG magic must not be decoded as ordinary filesystem text; chunks={chunks:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.metadata.source_type.as_ref() == "filesystem:binary-strings"),
        "PNG magic with printable payload should preserve recall through binary strings; chunks={chunks:?}"
    );
    assert!(
        chunks.iter().any(|chunk| chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with("img.dat"))),
        "PNG magic binary-string chunk path must identify the source file; chunks={chunks:?}"
    );
}
