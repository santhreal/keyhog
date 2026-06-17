//! R5-T archive adversarial: truncated gzip member does not panic.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn r5t_gzip_truncated_member_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("trunc.gz"), &[0x1f, 0x8b, 0x08, 0x00]).expect("write");
    let _ = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .count();
}
