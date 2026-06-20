//! Zero-byte tar file must not panic archive dispatch.

use super::support::collect_chunks;
use keyhog_sources::FilesystemSource;

#[test]
fn tar_zero_byte_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("empty.tar"), []).expect("empty tar");
    std::fs::write(dir.path().join("ok.txt"), "OK=1\n").expect("ok");

    let bodies: Vec<String> = collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()))
        .into_iter()
        .map(|c| c.data.to_string())
        .collect();
    assert!(bodies.iter().any(|b| b.contains("OK=1")));
}
