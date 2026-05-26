//! Contract: every chunk from FilesystemSource carries `metadata.path`.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::path::PathBuf;

#[test]
fn filesystem_chunks_carry_path_metadata() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("secrets.env");
    std::fs::write(&file, "TOKEN=abc123\n").expect("write fixture");

    let source = FilesystemSource::new(PathBuf::from(dir.path()));
    let chunks: Vec<_> = source
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("collect filesystem chunks");

    assert!(!chunks.is_empty(), "expected at least one chunk");
    for chunk in &chunks {
        let path = chunk
            .metadata
            .path
            .as_deref()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| {
                panic!(
                    "every filesystem chunk must have non-empty metadata.path, got {:?}",
                    chunk.metadata.path
                )
            });
        assert!(
            path.contains("secrets.env"),
            "path should reference the scanned file, got {path}"
        );
    }
}
