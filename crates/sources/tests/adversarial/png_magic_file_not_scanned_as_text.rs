//! PNG magic header must be rejected by text decode path.

use super::support::collect_chunks;
use keyhog_sources::FilesystemSource;

#[test]
fn png_magic_file_not_scanned_as_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.extend_from_slice(b"SECRET=hidden");
    std::fs::write(dir.path().join("img.dat"), bytes).expect("write");

    let chunks = collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(
        chunks
            .iter()
            .all(|chunk| chunk.metadata.source_type != "filesystem"),
        "PNG magic must not be decoded as ordinary filesystem text; chunks={chunks:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.metadata.source_type == "filesystem:binary-strings"),
        "PNG magic with printable payload should preserve recall through binary strings; chunks={chunks:?}"
    );
}
