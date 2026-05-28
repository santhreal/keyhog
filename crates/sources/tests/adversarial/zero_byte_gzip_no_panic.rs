//! Zero-byte `.gz` wrapper must not panic gzip dispatch.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn zero_byte_gzip_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("empty.gz"), []).expect("empty gz");
    std::fs::write(dir.path().join("side.txt"), "SIDE=ok\n").expect("side");

    let bodies: Vec<String> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(bodies.iter().any(|b| b.contains("SIDE=ok")));
}
