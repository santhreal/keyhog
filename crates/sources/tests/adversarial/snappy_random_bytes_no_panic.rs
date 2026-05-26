//! Random bytes with .sz extension must not panic extraction.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn snappy_random_bytes_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("bad.sz"), vec![0xFFu8; 128]).expect("write");
    std::fs::write(
        dir.path().join("fine.cfg"),
        "KEY=ok
",
    )
    .expect("write");

    let _: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
}
