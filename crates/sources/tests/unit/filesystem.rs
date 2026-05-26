use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::path::PathBuf;

#[test]
fn filesystem_source_yields_file_contents() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("secret.env");
    std::fs::write(&file, "TOKEN=abc123\n").unwrap();

    let source = FilesystemSource::new(PathBuf::from(dir.path()));
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert!(!chunks.is_empty());
    assert!(chunks[0].data.contains("TOKEN=abc123"));
}

#[test]
fn filesystem_source_missing_path_yields_nothing() {
    let source = FilesystemSource::new(PathBuf::from("/tmp/keyhog-missing-path-xyzzy-999"));
    assert!(source.chunks().next().is_none());
}
