#![cfg(feature = "web")]

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};

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
    assert_eq!(chunks[0].metadata.source_type, "web:js");
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
    assert_eq!(chunks[0].metadata.source_type, "web:wasm");
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
    assert_eq!(chunks[0].metadata.source_type, "web:sourcemap");
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
    assert_eq!(chunks[0].metadata.source_type, "web:js");
    assert!(
        chunks[0].data.as_ref().contains("plain_json_marker"),
        "generic JSON must remain a raw scanned web chunk, got {:?}",
        chunks
    );
}
