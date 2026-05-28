//! Truncated zip central directory must not panic extraction.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn corrupt_zip_truncated_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut bytes = b"PK\x03\x04".to_vec();
    bytes.extend_from_slice(&[0xDE; 128]);
    std::fs::write(dir.path().join("broken.zip"), bytes).expect("write");
    std::fs::write(dir.path().join("ok.txt"), "OK=1\n").expect("ok");

    let bodies: Vec<String> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(bodies.iter().any(|b| b.contains("OK=1")));
}
