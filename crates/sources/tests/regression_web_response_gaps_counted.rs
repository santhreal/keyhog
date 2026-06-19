#![cfg(feature = "web")]

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, WebSource};
use std::sync::{Mutex, MutexGuard};

static COUNTER_LOCK: Mutex<()> = Mutex::new(());

struct CounterGuard {
    _lock: MutexGuard<'static, ()>,
}

impl Drop for CounterGuard {
    fn drop(&mut self) {}
}

fn counter_guard() -> CounterGuard {
    let lock = COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    CounterGuard { _lock: lock }
}

fn loopback_calibration_source(url: String) -> WebSource {
    TestApi.web_source_with_autoroute_loopback_calibration(vec![url], true)
}

#[test]
fn clean_javascript_response_is_scanned_and_counter_clean() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _app = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/app.js");
        then.status(200)
            .header("content-type", "application/javascript")
            .body("const key = 'AKIAQYLPMN5HFIQR7XYA';\n"); // keyhog:ignore detector=aws-access-key
    });

    let chunks: Vec<_> = loopback_calibration_source(server.url("/app.js"))
        .chunks()
        .collect();
    let ok: Vec<_> = chunks
        .into_iter()
        .filter_map(|result| result.ok())
        .collect();
    assert_eq!(ok.len(), 1, "clean JavaScript URL should produce one chunk");
    assert!(
        ok[0].data.as_ref().contains("AKIAQYLPMN5HFIQR7XYA"), // keyhog:ignore detector=aws-access-key
        "chunk must carry response body"
    );

    let after = skip_counts();
    assert_eq!(
        after.total(),
        before.total(),
        "a scanned web body must not inflate skip counters"
    );
}

#[test]
fn non_success_status_is_error_and_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _missing = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/missing.js");
        then.status(404).body("not found");
    });

    let chunks: Vec<_> = loopback_calibration_source(server.url("/missing.js"))
        .chunks()
        .collect();
    assert_eq!(chunks.len(), 1, "non-success URL must yield one error");
    let err = chunks[0]
        .as_ref()
        .expect_err("404 response must be an error");
    assert!(
        err.to_string().contains("HTTP status 404"),
        "error should name the status, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "non-success WebSource response MUST bump SKIPPED_UNREADABLE"
    );
}

#[test]
fn malformed_sourcemap_is_raw_scanned_and_counted_partial() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let raw_marker = "sourcemap_raw_fallback_marker_2c7f7a";
    let _map = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/app.js.map");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(
                r#"{{"version":3,"sources":["app.ts"],"sourcesContent":["const token = '{raw_marker}';"]"#
            ));
    });

    let chunks: Vec<_> = loopback_calibration_source(server.url("/app.js.map"))
        .chunks()
        .collect();
    let ok: Vec<_> = chunks
        .into_iter()
        .filter_map(|result| result.ok())
        .collect();
    assert_eq!(
        ok.len(),
        1,
        "malformed source map should still produce one raw fallback chunk"
    );
    assert_eq!(ok[0].metadata.source_type, "web:sourcemap:raw");
    assert!(
        ok[0].data.contains(raw_marker),
        "raw fallback chunk must retain the malformed source map body"
    );

    let after = skip_counts();
    assert_eq!(
        after.structured_source_parse_failures - before.structured_source_parse_failures,
        1,
        "malformed WebSource source maps must surface a partial expansion coverage gap"
    );
    assert_eq!(
        after.total(),
        before.total(),
        "source-map parse failure is partial coverage because raw text was scanned"
    );
}

#[test]
fn partially_malformed_sourcemap_scans_decoded_entries_and_raw_map() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let parsed_marker = "sourcemap_decoded_marker_f711ab";
    let raw_marker = "sourcemap_malformed_embedded_marker_b91a22";
    let _map = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/mixed.js.map");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(
                r#"{{
                    "version": 3,
                    "sources": ["app.ts", "generated.ts"],
                    "sourcesContent": [
                        "const parsed = '{parsed_marker}';",
                        {{"text":"const hidden = '{raw_marker}';"}}
                    ]
                }}"#
            ));
    });

    let chunks: Vec<_> = loopback_calibration_source(server.url("/mixed.js.map"))
        .chunks()
        .collect();
    let ok: Vec<_> = chunks
        .into_iter()
        .filter_map(|result| result.ok())
        .collect();
    assert_eq!(
        ok.len(),
        2,
        "mixed source map must emit the valid decoded entry plus one raw fallback chunk"
    );
    assert!(
        ok.iter()
            .any(|chunk| chunk.metadata.source_type == "web:sourcemap"
                && chunk.data.contains(parsed_marker)),
        "valid sourcesContent string must still be decoded and scanned"
    );
    assert!(
        ok.iter()
            .any(|chunk| chunk.metadata.source_type == "web:sourcemap:raw"
                && chunk.data.contains(raw_marker)),
        "malformed sourcesContent object must be covered by raw-map scanning"
    );

    let after = skip_counts();
    assert_eq!(
        after.structured_source_parse_failures - before.structured_source_parse_failures,
        1,
        "mixed malformed source maps must surface a partial expansion coverage gap"
    );
    assert_eq!(
        after.total(),
        before.total(),
        "source-map partial expansion is raw-scanned partial coverage, not a whole-file skip"
    );
}

#[test]
fn malformed_sourcemap_source_names_keep_index_alignment_and_count_gap() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let first_marker = "sourcemap_first_source_marker_c83211";
    let second_marker = "sourcemap_second_source_marker_f61790";
    let _map = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/bad-sources.js.map");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(
                r#"{{
                    "version": 3,
                    "sources": [{{"bad":"name"}}, "app.ts"],
                    "sourcesContent": [
                        "const first = '{first_marker}';",
                        "const second = '{second_marker}';"
                    ]
                }}"#
            ));
    });

    let chunks: Vec<_> = loopback_calibration_source(server.url("/bad-sources.js.map"))
        .chunks()
        .collect();
    let ok: Vec<_> = chunks
        .into_iter()
        .filter_map(|result| result.ok())
        .collect();
    assert_eq!(
        ok.len(),
        2,
        "malformed source names must not force raw-only sourcemap scanning"
    );
    assert!(
        ok.iter().any(|chunk| {
            chunk.data.contains(first_marker)
                && chunk
                    .metadata
                    .path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("!source_0"))
        }),
        "the malformed first source name must keep its own synthetic index instead of stealing app.ts"
    );
    assert!(
        ok.iter().any(|chunk| {
            chunk.data.contains(second_marker)
                && chunk
                    .metadata
                    .path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("!app.ts"))
        }),
        "later valid source names must stay aligned with their original sourcesContent index"
    );

    let after = skip_counts();
    assert_eq!(
        after.structured_source_parse_failures - before.structured_source_parse_failures,
        1,
        "malformed source-name metadata must be visible as a structured parse gap"
    );
    assert_eq!(
        after.total(),
        before.total(),
        "source-name metadata gaps do not represent a whole-file skip"
    );
}

#[test]
fn over_cap_content_length_is_error_and_counted_over_max_size() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _huge = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/huge.js");
        then.status(200).body(vec![b'x'; 10_485_761]);
    });

    let chunks: Vec<_> = loopback_calibration_source(server.url("/huge.js"))
        .chunks()
        .collect();
    assert_eq!(chunks.len(), 1, "over-cap URL must yield one error");
    let err = chunks[0]
        .as_ref()
        .expect_err("over-cap response must be an error");
    assert!(
        err.to_string().contains("10485761") || err.to_string().contains("exceeds 10 MB"),
        "error should name the over-cap response size, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.over_max_size - before.over_max_size,
        1,
        "over-cap WebSource response MUST bump SKIPPED_OVER_MAX_SIZE"
    );
}

#[test]
fn invalid_wasm_magic_is_error_and_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _bad = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/module.wasm");
        then.status(200)
            .header("content-type", "application/wasm")
            .body("this is not wasm");
    });

    let chunks: Vec<_> = loopback_calibration_source(server.url("/module.wasm"))
        .chunks()
        .collect();
    assert_eq!(chunks.len(), 1, "invalid WASM URL must yield one error");
    let err = chunks[0]
        .as_ref()
        .expect_err("invalid WASM response must be an error");
    assert!(
        err.to_string().contains("WASM magic"),
        "error should name the invalid WASM magic, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "invalid WASM WebSource response MUST bump SKIPPED_UNREADABLE"
    );
}

#[test]
fn valid_wasm_without_printable_strings_is_counted_binary_gap() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let mut wasm = Vec::from([0x00, 0x61, 0x73, 0x6d]);
    wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    wasm.extend_from_slice(&[0x00; 64]);
    let _module = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/empty.wasm");
        then.status(200)
            .header("content-type", "application/wasm")
            .body(wasm);
    });

    let chunks: Vec<_> = loopback_calibration_source(server.url("/empty.wasm"))
        .chunks()
        .collect();
    assert!(
        chunks.is_empty(),
        "valid WASM with no printable strings yields no scannable chunks"
    );

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "valid WASM with no printable strings MUST bump SKIPPED_BINARY so the empty stream is not reported as full coverage"
    );
    assert_eq!(
        after.total() - before.total(),
        1,
        "WASM no-strings coverage gap must reach total skipped coverage"
    );
}
