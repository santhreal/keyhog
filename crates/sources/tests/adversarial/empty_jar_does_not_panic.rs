//! Empty jar archive must not panic directory scan.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use zip::ZipWriter;

#[test]
fn empty_jar_does_not_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = File::create(dir.path().join("empty.jar")).expect("create");
    ZipWriter::new(file).finish().expect("finish");
    std::fs::write(
        dir.path().join("side.txt"),
        "SIDE=ok
",
    )
    .expect("write");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid empty jar should not emit SourceError rows: {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "empty jar should emit no archive chunks while side file survives: {chunks:?}"
    );
    assert!(
        chunks[0].data.contains("SIDE=ok"),
        "side file must still scan when an empty jar is present: {chunks:?}"
    );
    assert!(
        chunks[0]
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with("side.txt")),
        "side chunk path must identify the scanned sibling, got {chunks:?}"
    );
}
