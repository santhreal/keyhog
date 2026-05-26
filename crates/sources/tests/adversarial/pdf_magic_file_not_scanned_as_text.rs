//! PDF magic header must be rejected by text decode path.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn pdf_magic_file_not_scanned_as_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut bytes = b"%PDF-1.7
"
    .to_vec();
    bytes.extend_from_slice(b"SECRET=should-not-appear-as-text");
    std::fs::write(dir.path().join("doc.pdf"), bytes).expect("write");

    let count = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .count();
    assert_eq!(count, 0, "PDF magic must skip text decode");
}
