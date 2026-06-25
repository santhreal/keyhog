//! Deep directory nesting must not stack-overflow the walker.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn deeply_nested_dirs_scan_continues() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut path = dir.path().to_path_buf();
    for i in 0..32 {
        path.push(format!("d{i}"));
        std::fs::create_dir(&path).expect("mkdir");
    }
    std::fs::write(path.join("deep.txt"), "DEEP=found\n").expect("deep");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "deep directory traversal should not emit SourceError rows: {errors:?}"
    );
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains("DEEP=found")
            && chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.ends_with("deep.txt"))),
        "deep leaf file must scan with path metadata; chunks={chunks:?}"
    );
}
