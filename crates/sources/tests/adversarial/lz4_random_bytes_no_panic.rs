//! Random bytes with .lz4 extension must not panic extraction.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn lz4_random_bytes_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut buf = Vec::with_capacity(512);
    for i in 0u32..512 {
        buf.push((i.wrapping_mul(1103515245).wrapping_add(12345) >> 16) as u8);
    }
    std::fs::write(dir.path().join("noise.lz4"), &buf).expect("write");
    std::fs::write(dir.path().join("keep.txt"), "SECRET=visible
").expect("write");

    let chunks: Vec<_> = FilesystemSource::new(dir.path().to_path_buf()).chunks().collect();
    assert!(
        chunks.iter().any(|r| r.as_ref().ok().is_some_and(|c| c.data.contains("visible"))),
        "scan must survive malformed lz4"
    );
}
