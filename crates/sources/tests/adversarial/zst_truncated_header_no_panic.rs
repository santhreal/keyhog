//! Truncated zstd payload must not panic the filesystem iterator.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn zst_truncated_header_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("broken.zst"),
        [0x28, 0xb5, 0x2f, 0xfd, 0x00],
    )
    .expect("write");
    std::fs::write(
        dir.path().join("ok.env"),
        "TOKEN=still-here
",
    )
    .expect("write");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let bodies: Vec<String> = source
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies.iter().any(|b| b.contains("still-here")),
        "valid neighbor file must still scan; got {bodies:?}"
    );
}
