use keyhog_core::Source;
use keyhog_sources::{skip_counts, testing::reset_skip_counters, FilesystemSource};

#[test]
fn malformed_har_shape_counts_partial_parse_gap_and_scans_raw_text() {
    reset_skip_counters();

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("broken.har");
    let raw_marker = "har_raw_fallback_marker_7f0f6b45";
    std::fs::write(
        &path,
        format!(
            r#"{{"log": {{"entries": [{{"request": {{"method": "GET", "url": "https://example.test", "headers": [{{"name": "X-Marker", "value": "{raw_marker}"}}]"#
        ),
    )
    .expect("write malformed HAR");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source
        .chunks()
        .map(|chunk| chunk.expect("filesystem chunk"))
        .collect();

    assert!(
        chunks.iter().any(|chunk| chunk.data.contains(raw_marker)),
        "malformed HAR must still be scanned as raw text; chunks={chunks:?}"
    );
    assert!(
        chunks
            .iter()
            .filter_map(|chunk| chunk.metadata.path.as_deref())
            .any(|chunk_path| chunk_path.ends_with("broken.har")),
        "raw fallback chunk must retain the source path; chunks={chunks:?}"
    );

    let counts = skip_counts();
    assert_eq!(
        counts.structured_source_parse_failures, 1,
        "HAR-shaped parse failure must be surfaced as a partial source coverage gap"
    );
    assert_eq!(
        counts.total(),
        0,
        "structured-source parse failure is partial coverage because raw text was scanned"
    );

    reset_skip_counters();
}
