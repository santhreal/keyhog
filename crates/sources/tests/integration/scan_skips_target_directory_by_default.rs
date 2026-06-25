//! Default ignore rules must skip target/ build artifacts.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn scan_skips_target_directory_by_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target").join("debug");
    std::fs::create_dir_all(&target).expect("mkdir");
    std::fs::write(
        target.join("embedded.env"),
        "TOKEN=must-not-scan-target-dir
",
    )
    .expect("write");
    std::fs::write(
        dir.path().join("src.env"),
        "TOKEN=scan-root
",
    )
    .expect("write");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "default target exclude fixture must not emit SourceError rows, got {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "only the root file should be scanned; got {chunks:?}"
    );
    assert_eq!(chunks[0].metadata.source_type, "filesystem");
    assert!(
        chunks[0]
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with("src.env")),
        "surviving chunk must carry root path metadata, got {:?}",
        chunks[0].metadata.path
    );
    let bodies: Vec<String> = chunks.iter().map(|c| c.data.to_string()).collect();
    assert!(bodies.iter().any(|b| b.contains("scan-root")));
    assert!(
        !bodies
            .iter()
            .any(|b| b.contains("must-not-scan-target-dir")),
        "target/ must be ignored by default"
    );
}
