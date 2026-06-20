//! Zero-byte binary-looking file must not panic binary dispatch.

use super::support::collect_chunks;
use keyhog_sources::FilesystemSource;

#[test]
fn binary_zero_byte_elf_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("empty.bin"), []).expect("empty bin");
    std::fs::write(dir.path().join("note.txt"), "NOTE=ok\n").expect("note");

    let bodies: Vec<String> = collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()))
        .into_iter()
        .map(|c| c.data.to_string())
        .collect();
    assert!(bodies.iter().any(|b| b.contains("NOTE=ok")));
}
