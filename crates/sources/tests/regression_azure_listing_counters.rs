#![cfg(feature = "azure")]

//! Azure Blob listing/skip counter regressions.
//!
//! Companion to `regression_azure_blob_object_drops_counted.rs`: this binary
//! nails down that every *blob drop* (binary-extension, binary content-type,
//! over-cap, unreadable) bumps its skip counter EXACTLY ONCE, that a *listing
//! failure* records exactly one `unreadable` skip, and that the *scanned blob
//! total* is exact across a mixed listing (some scanned, some dropped, empty
//! blobs silently ignored). Every assertion is a concrete count / string / byte.
//!
//! The COUNTER_LOCK serialization + reset-before/read-after delta pattern
//! mirrors the sibling file so the global skip counters are read race-free.

mod support;

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, AzureBlobSource, SourceLimits};
use std::sync::{Mutex, MutexGuard};
use support::split_chunk_results;

static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn counter_guard() -> MutexGuard<'static, ()> {
    // httpmock points the cloud endpoint at 127.0.0.1, which the default cloud
    // SSRF endpoint screen refuses. Opt into the loud, default-off allowance for
    // this (separate) test binary while holding COUNTER_LOCK so the env write and
    // the global skip counters can never race a parallel test.
    let guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::env::set_var("KEYHOG_ALLOW_PRIVATE_CLOUD_ENDPOINT", "1");
    guard
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

fn list_mock<'a>(server: &'a httpmock::MockServer, body: String) -> httpmock::Mock<'a> {
    server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container")
            .query_param("restype", "container")
            .query_param("comp", "list");
        then.status(200)
            .header("content-type", "application/xml")
            .body(body);
    })
}

// ----- blob drops each bump their counter EXACTLY once -----

#[test]
fn single_binary_extension_blob_drop_bumps_binary_exactly_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = list_mock(
        &server,
        listing(&blob("archive.zip", 512, "application/octet-stream")),
    );
    let object_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/archive.zip");
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 0, "binary-extension blob must not be scanned");
    assert_eq!(errors.len(), 1, "one error row for the single dropped blob");
    let error = errors[0].to_string();
    assert!(
        error.contains("extension is treated as binary/container content")
            && error.contains("blob was not scanned"),
        "got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "binary bumped exactly once"
    );
    assert_eq!(
        after.over_max_size, before.over_max_size,
        "over_max_size untouched"
    );
    assert_eq!(after.unreadable, before.unreadable, "unreadable untouched");
    assert_eq!(
        after.total() - before.total(),
        1,
        "exactly one skip recorded total"
    );
    assert_eq!(
        object_get.calls(),
        0,
        "binary-extension blob must not be fetched"
    );
}

#[test]
fn two_binary_extension_blobs_bump_binary_twice() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let body = format!(
        "{}{}",
        blob("bundle.zip", 100, "application/octet-stream"),
        blob("payload.rar", 200, "application/octet-stream"),
    );
    let _list = list_mock(&server, listing(&body));

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 0, "no binary-extension blob is scanned");
    assert_eq!(errors.len(), 2, "one error row per dropped blob");

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        2,
        "binary bumped once per dropped blob"
    );
    assert_eq!(after.total() - before.total(), 2, "exactly two skips total");
}

#[test]
fn binary_listing_content_type_image_jpeg_drops_without_get() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    // Text-looking key, but the listing content-type is image/* => binary drop
    // BEFORE any object GET.
    let _list = list_mock(&server, listing(&blob("thumbnail.txt", 512, "image/jpeg")));
    let object_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/thumbnail.txt");
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 0, "binary content-type blob must not be scanned");
    assert_eq!(errors.len(), 1, "one error row for the dropped blob");
    let error = errors[0].to_string();
    assert!(
        error.contains("listing reports binary content-type")
            && error.contains("image/jpeg")
            && error.contains("blob was not scanned"),
        "got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "binary bumped exactly once"
    );
    assert_eq!(after.unreadable, before.unreadable, "unreadable untouched");
    assert_eq!(
        object_get.calls(),
        0,
        "binary content-type blob must not be fetched"
    );
}

#[test]
fn over_cap_listed_size_drops_without_get_bumps_over_max_size() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();
    let cap = SourceLimits::default().azure_blob_bytes;

    let server = httpmock::MockServer::start();
    let _list = list_mock(&server, listing(&blob("huge.log", cap + 1, "text/plain")));
    let object_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/huge.log");
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 0, "over-cap listed blob must not be scanned");
    assert_eq!(errors.len(), 1, "one error row for the over-cap blob");
    let error = errors[0].to_string();
    assert!(
        error.contains("listed size")
            && error.contains("exceeds the per-blob byte cap")
            && error.contains("blob was not scanned"),
        "got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.over_max_size - before.over_max_size,
        1,
        "over_max_size bumped exactly once"
    );
    assert_eq!(after.binary, before.binary, "binary untouched");
    assert_eq!(after.unreadable, before.unreadable, "unreadable untouched");
    assert_eq!(
        object_get.calls(),
        0,
        "over-cap blob must not be fetched (drop is listing-side)"
    );
}

// ----- empty blob: a silent drop that is NOT counted -----

#[test]
fn empty_blob_is_dropped_without_scan_or_skip_count() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = list_mock(&server, listing(&blob("empty.txt", 0, "text/plain")));
    let object_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/empty.txt");
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect();
    assert_eq!(
        rows.len(),
        0,
        "a zero-length blob yields neither a chunk nor an error row"
    );

    let after = skip_counts();
    assert_eq!(
        after.total(),
        before.total(),
        "empty blob must not inflate any skip counter"
    );
    assert_eq!(
        object_get.calls(),
        0,
        "zero-length blob must not be fetched"
    );
}

// ----- listing failure records exactly one unreadable skip -----

#[test]
fn non_success_listing_counts_unreadable_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container")
            .query_param("restype", "container")
            .query_param("comp", "list");
        then.status(503).body("unavailable");
    });

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect();
    assert_eq!(rows.len(), 1, "a failed listing surfaces exactly one row");
    let error = rows[0]
        .as_ref()
        .expect_err("a failed listing must be an error row")
        .to_string();
    assert!(
        error.contains("source listing failed")
            && error.contains("container request returned")
            && error.contains("503")
            && error.contains("blobs were not scanned"),
        "got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "listing failure bumped unreadable once"
    );
    assert_eq!(
        after.total() - before.total(),
        1,
        "exactly one skip recorded total"
    );
    assert_eq!(
        after.over_max_size, before.over_max_size,
        "not mislabeled over_max_size"
    );
}

#[test]
fn malformed_listing_counts_unreadable_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    // Truncated XML: passes the DOCTYPE/entity screen but fails deserialization.
    let _list = list_mock(&server, "<EnumerationResults><Blobs>".to_string());

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "a malformed listing surfaces exactly one row"
    );
    let error = rows[0]
        .as_ref()
        .expect_err("a malformed listing must be an error row")
        .to_string();
    assert!(
        error.contains("source listing failed")
            && error.contains("failed to parse listing response")
            && error.contains("blobs were not scanned"),
        "got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "malformed listing bumped unreadable once"
    );
    assert_eq!(
        after.total() - before.total(),
        1,
        "exactly one skip recorded total"
    );
}

// ----- per-object GET failures -----

#[test]
fn non_success_object_get_counts_unreadable_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = list_mock(&server, listing(&blob("gone.txt", 32, "text/plain")));
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/gone.txt");
        then.status(500).body("ServerError");
    });

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "a failed object GET surfaces exactly one row"
    );
    let error = rows[0]
        .as_ref()
        .expect_err("a failed object GET must be an error row")
        .to_string();
    assert!(
        error.contains("GET returned 500") && error.contains("blob was not scanned"),
        "got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "object GET failure bumped unreadable once"
    );
    assert_eq!(after.binary, before.binary, "binary untouched");
}

#[test]
fn object_get_content_length_over_cap_counts_over_max_size() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    // Listed size (4) is under the cap so the listing-side gate passes; the GET
    // response Content-Length (17) exceeds the per-object cap of 8 and is dropped.
    let mut limits = SourceLimits::default();
    limits.azure_blob_bytes = 8;

    let server = httpmock::MockServer::start();
    let _list = list_mock(&server, listing(&blob("small-listed.txt", 4, "text/plain")));
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/small-listed.txt");
        then.status(200)
            .header("content-type", "text/plain")
            .body("0123456789012345\n"); // 17 bytes
    });

    let rows: Vec<_> = TestApi
        .azure_blob_source_with_limits(container_url(&server), limits)
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 0, "over-cap GET body must not be scanned");
    assert_eq!(errors.len(), 1, "one error row for the over-cap GET body");
    let error = errors[0].to_string();
    assert!(
        error.contains("Content-Length 17 exceeds the per-object byte cap 8")
            && error.contains("blob was not scanned"),
        "got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.over_max_size - before.over_max_size,
        1,
        "over_max_size bumped once"
    );
    assert_eq!(
        after.unreadable, before.unreadable,
        "not mislabeled unreadable"
    );
}

#[test]
fn octet_stream_binary_body_counts_binary_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    // Text-looking key + octet-stream listing type => passes prefilter and is
    // fetched; the GET body is binary (NULs) so it is dropped as binary.
    let _list = list_mock(
        &server,
        listing(&blob("data.txt", 64, "application/octet-stream")),
    );
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/data.txt");
        then.status(200)
            .header("content-type", "application/octet-stream")
            .body(vec![0x00u8, 0x01, 0x02, 0x00, 0xFF, 0xFE, 0x00, 0x80]);
    });

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 0, "binary octet-stream body must not be scanned");
    assert_eq!(errors.len(), 1, "one error row for the binary body");
    let error = errors[0].to_string();
    assert!(
        error.contains("octet-stream body is binary after capped decode")
            && error.contains("blob was not scanned"),
        "got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "binary bumped exactly once"
    );
    assert_eq!(
        after.unreadable, before.unreadable,
        "not mislabeled unreadable"
    );
}

// ----- scanned blob total is EXACT across a mixed listing -----

#[test]
fn mixed_listing_scanned_and_dropped_blob_total_is_exact() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    // 4 listed blobs: 2 scanned text, 1 binary-extension drop, 1 empty (silent).
    let body = format!(
        "{}{}{}{}",
        blob("alpha.txt", 40, "text/plain"),
        blob("nested/beta.txt", 40, "text/plain"),
        blob("archive.zip", 512, "application/octet-stream"),
        blob("empty.txt", 0, "text/plain"),
    );
    let _list = list_mock(&server, listing(&body));
    let _alpha = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/alpha.txt");
        then.status(200)
            .header("content-type", "text/plain")
            .body("alpha body\n");
    });
    let _beta = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/nested/beta.txt");
        then.status(200)
            .header("content-type", "text/plain")
            .body("beta body\n");
    });
    let zip_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/archive.zip");
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 2, "exactly the two text blobs are scanned");
    assert_eq!(
        errors.len(),
        1,
        "exactly the binary-extension blob errors; empty is silent"
    );

    let mut paths: Vec<&str> = ok
        .iter()
        .filter_map(|c| c.metadata.path.as_deref())
        .collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        vec![
            "azblob://127.0.0.1/container/alpha.txt",
            "azblob://127.0.0.1/container/nested/beta.txt",
        ],
        "scanned chunk paths must be exact"
    );

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "only the zip is counted binary"
    );
    assert_eq!(
        after.over_max_size, before.over_max_size,
        "no over_max_size"
    );
    assert_eq!(after.unreadable, before.unreadable, "no unreadable");
    assert_eq!(
        after.total() - before.total(),
        1,
        "exactly one skip across the mixed listing"
    );
    assert_eq!(
        zip_get.calls(),
        0,
        "binary-extension blob must not be fetched"
    );
}

// ----- scanned-blob positive contract (bytes / path / size) -----

#[test]
fn scanned_blob_carries_exact_body_path_and_size() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = list_mock(
        &server,
        listing(&blob("nested/dir/config.txt", 40, "text/plain")),
    );
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/nested/dir/config.txt");
        then.status(200)
            .header("content-type", "text/plain")
            .body("service endpoint value\n");
    });

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("clean scan must not error");
    assert_eq!(rows.len(), 1, "one chunk for the single scanned blob");
    assert_eq!(
        rows[0].data.as_ref(),
        "service endpoint value\n",
        "chunk carries the exact body"
    );
    assert_eq!(
        rows[0].metadata.path.as_deref(),
        Some("azblob://127.0.0.1/container/nested/dir/config.txt"),
        "display path preserves the nested key"
    );
    assert_eq!(
        rows[0].metadata.size_bytes,
        Some(40),
        "size_bytes carries the listed length"
    );
    assert_eq!(
        &*rows[0].metadata.source_type,
        "azure_blob",
        "source_type is azure_blob"
    );

    let after = skip_counts();
    assert_eq!(
        after.total(),
        before.total(),
        "a clean scan touches no skip counter"
    );
}

#[test]
fn clean_multi_blob_scan_does_not_touch_skip_counters() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let body = format!(
        "{}{}{}",
        blob("one.txt", 16, "text/plain"),
        blob("two.log", 16, "text/plain"),
        blob("three.json", 16, "application/json"),
    );
    let _list = list_mock(&server, listing(&body));
    for name in ["one.txt", "two.log", "three.json"] {
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/container/{name}"));
            then.status(200)
                .header("content-type", "text/plain")
                .body(format!("body of {name}\n"));
        });
    }

    let rows: Vec<_> = AzureBlobSource::new(container_url(&server))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("clean multi-blob scan must not error");
    assert_eq!(rows.len(), 3, "all three text blobs scanned");

    let after = skip_counts();
    assert_eq!(
        after.total(),
        before.total(),
        "clean scan is a no-op on skip counters"
    );
    assert_eq!(after.binary, before.binary, "binary untouched");
    assert_eq!(after.unreadable, before.unreadable, "unreadable untouched");
    assert_eq!(
        after.over_max_size, before.over_max_size,
        "over_max_size untouched"
    );
}
