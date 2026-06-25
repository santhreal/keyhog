//! PDF magic header must be rejected by text decode path.

use super::support::collect_chunks;
use keyhog_sources::FilesystemSource;

#[test]
fn pdf_magic_file_not_scanned_as_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut bytes = b"%PDF-1.7
"
    .to_vec();
    bytes.extend_from_slice(b"SECRET=should-not-appear-as-text");
    std::fs::write(dir.path().join("doc.dat"), bytes).expect("write");

    let chunks = collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(
        chunks
            .iter()
            .all(|chunk| chunk.metadata.source_type != "filesystem"),
        "PDF magic must not be decoded as ordinary filesystem text; chunks={chunks:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.metadata.source_type == "filesystem:binary-strings"),
        "PDF magic with printable payload should preserve recall through binary strings; chunks={chunks:?}"
    );
}
