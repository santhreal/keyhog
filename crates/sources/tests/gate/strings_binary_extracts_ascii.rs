//! LR1-A8 replacement gate: `strings.rs` ASCII extraction from binary blob.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn strings_source_emits_one_chunk_for_small_binary() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bin.dat"), b"secret=abc1234567890").unwrap();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().collect();
    assert_eq!(chunks.len(), 1);
    let chunk = chunks[0].as_ref().unwrap();
    assert!(chunk.data.contains("secret="));
}
