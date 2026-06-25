//! Very long path components must not panic the walker.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn max_path_length_component_handled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let long_name = "a".repeat(240);
    std::fs::write(dir.path().join(format!("{long_name}.txt")), "LONGNAME=1\n").expect("long");
    std::fs::write(dir.path().join("short.txt"), "SHORT=ok\n").expect("short");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "long filename entries should not emit SourceError rows: {errors:?}"
    );

    assert!(
        chunks.iter().any(|chunk| chunk.data.contains("SHORT=ok")
            && chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.ends_with("short.txt"))),
        "walker must survive long filename entries and scan the sibling path; chunks={chunks:?}"
    );
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains("LONGNAME=1")
            && chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.contains(&long_name))),
        "long filename entry itself must scan with path metadata; chunks={chunks:?}"
    );
}
