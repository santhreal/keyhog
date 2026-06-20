//! PNG magic header must be rejected by text decode path.

use super::support::collect_chunks;
use keyhog_sources::FilesystemSource;

#[test]
fn png_magic_file_not_scanned_as_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.extend_from_slice(b"SECRET=hidden");
    std::fs::write(dir.path().join("img.png"), bytes).expect("write");

    let count = collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()))
        .into_iter()
        .count();
    assert_eq!(count, 0);
}
