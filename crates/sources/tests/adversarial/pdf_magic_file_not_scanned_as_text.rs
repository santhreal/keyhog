//! PDF magic header must be rejected by text decode path.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn pdf_magic_file_not_scanned_as_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut bytes = b"%PDF-1.7
"
    .to_vec();
    bytes.extend_from_slice(b"SECRET=should-not-appear-as-text");
    std::fs::write(dir.path().join("doc.dat"), bytes).expect("write");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "PDF magic binary-string recovery should not emit SourceError rows: {errors:?}"
    );
    assert!(
        chunks
            .iter()
            .all(|chunk| chunk.metadata.source_type.as_ref() != "filesystem"),
        "PDF magic must not be decoded as ordinary filesystem text; chunks={chunks:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.metadata.source_type.as_ref() == "filesystem:binary-strings"),
        "PDF magic with printable payload should preserve recall through binary strings; chunks={chunks:?}"
    );
    assert!(
        chunks.iter().any(|chunk| chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with("doc.dat"))),
        "PDF magic binary-string chunk path must identify the source file; chunks={chunks:?}"
    );
}
