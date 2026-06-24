use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

#[test]
fn malformed_har_shape_counts_partial_parse_gap_and_scans_raw_text() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

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

    TestApi.reset_skip_counters();
}

#[test]
fn malformed_har_base64_body_counts_partial_decode_gap_and_scans_raw_text() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("capture.har");
    let raw_secret = "AKIAQYLPMN5HFIQR7XYA not really base64 @@@"; // keyhog:ignore detector=aws-access-key (synthetic test fixture)
    std::fs::write(
        &path,
        format!(
            r#"{{
              "log": {{
                "version": "1.2",
                "creator": {{"name": "test", "version": "1"}},
                "entries": [{{
                  "request": {{
                    "method": "GET",
                    "url": "https://example.test/api",
                    "headers": [],
                    "queryString": []
                  }},
                  "response": {{
                    "status": 200,
                    "statusText": "OK",
                    "headers": [],
                    "content": {{
                      "mimeType": "application/json",
                      "encoding": "base64",
                      "text": "{raw_secret}"
                    }}
                  }}
                }}]
              }}
            }}"#
        ),
    )
    .expect("write HAR");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source
        .chunks()
        .map(|chunk| chunk.expect("filesystem chunk"))
        .collect();

    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.metadata.source_type == "wire:har:response"
                && chunk.data.contains("AKIAQYLPMN5HFIQR7XYA")),
        "malformed declared-base64 HAR body must still be scanned raw; chunks={chunks:?}"
    );
    assert!(
        chunks
            .iter()
            .filter(|chunk| chunk.metadata.source_type == "wire:har:response")
            .filter_map(|chunk| chunk.metadata.path.as_deref())
            .any(|chunk_path| {
                chunk_path.ends_with("capture.har#https://example.test/api")
                    || (chunk_path.contains("capture.har")
                        && chunk_path.contains("https://example.test/api"))
            }),
        "malformed declared-base64 HAR response chunk must retain filesystem path and URL context; chunks={chunks:?}"
    );

    let counts = skip_counts();
    assert_eq!(
        counts.structured_source_parse_failures, 1,
        "malformed declared-base64 HAR body must surface as a partial structured decode gap"
    );
    assert_eq!(
        counts.total(),
        0,
        "malformed declared-base64 HAR body is partial coverage because raw text was scanned"
    );

    TestApi.reset_skip_counters();
}
