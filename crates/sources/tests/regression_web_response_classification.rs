#![cfg(feature = "web")]

use keyhog_core::Source;
use keyhog_sources::testing::TestApi;

fn loopback_source(url: String) -> keyhog_sources::WebSource {
    TestApi.web_source_with_autoroute_loopback_calibration(vec![url], true)
}

#[test]
fn successful_non_200_response_body_is_scanned() {
    let server = httpmock::MockServer::start();
    let _app = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/app.js");
        then.status(203)
            .header("content-type", "application/javascript")
            .body("const key = 'AKIAQYLPMN5HFIQR7XYA';\n"); // keyhog:ignore detector=aws-access-key
    });

    let chunks: Vec<_> = loopback_source(server.url("/app.js"))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("2xx response should be scanned");

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].metadata.source_type.as_ref(), "web:js");
    assert!(
        chunks[0].data.as_ref().contains("AKIAQYLPMN5HFIQR7XYA"), // keyhog:ignore detector=aws-access-key
        "2xx non-200 body must be scanned, got {:?}",
        chunks
    );
}

#[test]
fn extensionless_wasm_routes_by_content_type() {
    let mut wasm = Vec::from([0x00, 0x61, 0x73, 0x6d]);
    wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    wasm.extend_from_slice(b"extensionless_secret");

    let server = httpmock::MockServer::start();
    let _module = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/module");
        then.status(200)
            .header("content-type", "application/wasm")
            .body(wasm);
    });

    let chunks: Vec<_> = loopback_source(server.url("/module"))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("extensionless wasm should be scanned");

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].metadata.source_type.as_ref(), "web:wasm");
    assert!(
        chunks[0].data.as_ref().contains("extensionless_secret"),
        "WASM content-type must route to printable-string extraction, got {:?}",
        chunks
    );
}

#[test]
fn extensionless_sourcemap_routes_by_content_type() {
    let server = httpmock::MockServer::start();
    let _map = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/bundle");
        then.status(200)
            .header("content-type", "application/json; charset=utf-8")
            .body(
                r#"{"version":3,"sources":["app.ts"],"sourcesContent":["const marker='decoded_sourcemap_marker';"],"mappings":""}"#,
            );
    });

    let chunks: Vec<_> = loopback_source(server.url("/bundle"))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("extensionless source map should be scanned");

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].metadata.source_type.as_ref(), "web:sourcemap");
    assert!(
        chunks[0].data.as_ref().contains("decoded_sourcemap_marker"),
        "JSON source map content-type must route to sourcemap expansion, got {:?}",
        chunks
    );
}

#[test]
fn ordinary_json_response_stays_raw_web_text() {
    let server = httpmock::MockServer::start();
    let _json = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/config");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"token":"plain_json_marker"}"#);
    });

    let chunks: Vec<_> = loopback_source(server.url("/config"))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("ordinary JSON should still be scanned");

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].metadata.source_type.as_ref(), "web:js");
    assert!(
        chunks[0].data.as_ref().contains("plain_json_marker"),
        "generic JSON must remain a raw scanned web chunk, got {:?}",
        chunks
    );
}

const BOUNDED_WEB_CHUNK_BYTES: usize = 256 * 1024;

fn assert_gapless_web_body(chunks: &[keyhog_core::Chunk], expected: &str, source_type: &str) {
    assert!(chunks.len() > 1);
    assert!(chunks.iter().all(|chunk| {
        chunk.metadata.source_type.as_ref() == source_type
            && chunk.data.len() <= BOUNDED_WEB_CHUNK_BYTES
    }));
    assert_eq!(
        chunks
            .iter()
            .map(|chunk| chunk.data.as_ref())
            .collect::<String>(),
        expected
    );
    for pair in chunks.windows(2) {
        assert_eq!(
            pair[1].metadata.base_offset,
            pair[0].metadata.base_offset + pair[0].data.len()
        );
        assert_eq!(
            pair[1].metadata.base_line,
            pair[0].metadata.base_line
                + pair[0]
                    .data
                    .as_bytes()
                    .iter()
                    .filter(|&&byte| byte == b'\n')
                    .count()
        );
    }
}

#[test]
fn large_javascript_response_emits_bounded_utf8_chunks() {
    let body = format!(
        "{}é{}\n{}",
        "x".repeat(BOUNDED_WEB_CHUNK_BYTES - 1),
        "y".repeat(BOUNDED_WEB_CHUNK_BYTES),
        "z".repeat(31)
    );
    let server = httpmock::MockServer::start();
    let _app = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/large.js");
        then.status(200)
            .header("content-type", "application/javascript")
            .body(body.clone());
    });

    let chunks = loopback_source(server.url("/large.js"))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("large JavaScript response should be scanned");

    assert_gapless_web_body(&chunks, &body, "web:js");
}

#[test]
fn large_sourcemap_entry_emits_bounded_chunks() {
    let source = format!(
        "{}\n{}",
        "const x = 'value';".repeat(20_000),
        "const end = true;"
    );
    let body = serde_json::json!({
        "version": 3,
        "sources": ["large.ts"],
        "sourcesContent": [source],
        "mappings": ""
    })
    .to_string();
    let server = httpmock::MockServer::start();
    let _map = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/large.js.map");
        then.status(200)
            .header("content-type", "application/json")
            .body(body);
    });

    let chunks = loopback_source(server.url("/large.js.map"))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("large source map should be scanned");

    assert_gapless_web_body(&chunks, &source, "web:sourcemap");
}

#[test]
fn large_wasm_string_stream_emits_bounded_chunks() {
    let printable = "w".repeat(BOUNDED_WEB_CHUNK_BYTES * 2 + 17);
    let mut wasm = Vec::from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    wasm.extend_from_slice(printable.as_bytes());
    let server = httpmock::MockServer::start();
    let _module = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/large.wasm");
        then.status(200)
            .header("content-type", "application/wasm")
            .body(wasm);
    });

    let chunks = loopback_source(server.url("/large.wasm"))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("large WASM response should be scanned");

    assert_gapless_web_body(&chunks, &printable, "web:wasm");
}
