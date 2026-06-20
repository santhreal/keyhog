#![cfg(feature = "azure")]

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, AzureBlobSource};
use std::sync::{Mutex, MutexGuard};

static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn counter_guard() -> MutexGuard<'static, ()> {
    COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn blob(name: &str, size: u64, content_type: &str) -> String {
    format!(
        r#"<Blob><Name>{name}</Name><Properties><Content-Length>{size}</Content-Length><Content-Type>{content_type}</Content-Type></Properties></Blob>"#
    )
}

fn listing(blobs: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://account.blob.core.windows.net/" ContainerName="container">
  <Blobs>{blobs}</Blobs>
  <NextMarker />
</EnumerationResults>"#
    )
}

fn container_url(server: &httpmock::MockServer) -> String {
    format!("{}/container?sv=2024-11-04&sig=regression", server.url(""))
}

#[test]
fn plain_text_blob_is_scanned_and_sas_query_is_preserved() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container")
            .query_param("sv", "2024-11-04")
            .query_param("sig", "regression")
            .query_param("restype", "container")
            .query_param("comp", "list");
        then.status(200)
            .header("content-type", "application/xml")
            .body(listing(&blob("config.txt", 40, "text/plain")));
    });
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/config.txt")
            .query_param("sv", "2024-11-04")
            .query_param("sig", "regression");
        then.status(200)
            .header("content-type", "text/plain")
            .body("aws_key=AKIAQYLPMN5HFIQR7XYA\n"); // keyhog:ignore detector=aws-access-key
    });

    let ok: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(ok.len(), 1, "Azure text blob should produce one chunk");
    assert!(
        ok[0].data.as_ref().contains("AKIAQYLPMN5HFIQR7XYA"), // keyhog:ignore detector=aws-access-key
        "chunk must carry blob body"
    );
    assert_eq!(
        ok[0].metadata.path.as_deref(),
        Some("azblob://127.0.0.1/container/config.txt")
    );

    let after = skip_counts();
    assert_eq!(
        after.total(),
        before.total(),
        "a scanned text blob must not inflate skip counters"
    );
}

#[test]
fn binary_extension_blob_is_counted_binary_without_get() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container")
            .query_param("restype", "container")
            .query_param("comp", "list");
        then.status(200)
            .header("content-type", "application/xml")
            .body(listing(&blob("bundle.zip", 512, "application/zip")));
    });
    let object_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/bundle.zip");
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let ok: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(ok.len(), 0, "binary-extension blob must not be scanned");

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "Azure binary/container extension prefilter MUST bump SKIPPED_BINARY"
    );
    assert_eq!(
        object_get.calls(),
        0,
        "binary-extension blob must not be fetched"
    );
}

#[test]
fn non_success_get_is_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container")
            .query_param("restype", "container")
            .query_param("comp", "list");
        then.status(200)
            .header("content-type", "application/xml")
            .body(listing(&blob("forbidden.txt", 32, "text/plain")));
    });
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/forbidden.txt");
        then.status(403).body("AuthorizationFailure");
    });

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "failed blob GET must surface one source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("failed blob GET must be an error row");
    assert!(
        err.to_string().contains("GET returned 403")
            && err.to_string().contains("blob was not scanned"),
        "error should name the unscanned Azure blob, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "Azure non-success blob GET MUST bump SKIPPED_UNREADABLE"
    );
}

#[test]
fn non_utf8_text_labelled_blob_is_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container")
            .query_param("restype", "container")
            .query_param("comp", "list");
        then.status(200)
            .header("content-type", "application/xml")
            .body(listing(&blob("lies.txt", 4, "text/plain")));
    });
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/lies.txt");
        then.status(200)
            .header("content-type", "text/plain")
            .body(vec![0xFFu8, 0xFE, 0x00, 0x80]);
    });

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "non-UTF-8 Azure blob must surface one source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("non-UTF-8 Azure blob must be an error row");
    assert!(
        err.to_string().contains("failed UTF-8 decode")
            && err.to_string().contains("blob was not scanned"),
        "error should name the undecodable Azure blob, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "Azure non-UTF-8 text-labelled body MUST bump SKIPPED_UNREADABLE"
    );
}

#[test]
fn max_objects_limit_is_counted_source_truncated() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container")
            .query_param("restype", "container")
            .query_param("comp", "list");
        then.status(200)
            .header("content-type", "application/xml")
            .body(listing(&format!(
                "{}{}",
                blob("first.txt", 16, "text/plain"),
                blob("second.txt", 16, "text/plain")
            )));
    });
    let _first = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/first.txt");
        then.status(200)
            .header("content-type", "text/plain")
            .body("first blob\n");
    });
    let second_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/second.txt");
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = TestApi
        .azure_blob_source_with_max_objects(container_url(&server), 1)
        .chunks()
        .collect();
    let ok: Vec<_> = rows.iter().filter_map(|row| row.as_ref().ok()).collect();
    let errors: Vec<_> = rows.iter().filter_map(|row| row.as_ref().err()).collect();
    assert_eq!(ok.len(), 1, "first blob within cap should be scanned");
    assert_eq!(
        errors.len(),
        1,
        "max_objects truncation must surface one source error"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("source scan was truncated")
            && err.contains("remaining objects were not scanned"),
        "error should describe partial Azure Blob coverage, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "Azure max_objects truncation MUST bump SOURCE_TRUNCATED"
    );
    assert_eq!(
        second_get.calls(),
        0,
        "blobs beyond the cap must not be fetched"
    );
}
