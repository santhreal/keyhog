//! Minified bundle filenames must be excluded from scanning.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn filesystem_minified_js_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("app.min.js"),
        "const TOKEN='ghp_shouldNotScanMinifiedBundle';",
    )
    .expect("write");
    std::fs::write(
        dir.path().join("real.env"),
        "TOKEN=scan-me
",
    )
    .expect("write");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "minified filename exclusion should not emit SourceError rows: {errors:?}"
    );
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains("scan-me")
            && chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.ends_with("real.env"))),
        "non-minified file must scan with path metadata; chunks={chunks:?}"
    );
    assert!(
        !chunks
            .iter()
            .any(|chunk| chunk.data.contains("ghp_shouldNotScanMinifiedBundle")),
        "minified bundle must be skipped"
    );
}
