#![cfg(any(feature = "azure", feature = "gcs", feature = "s3"))]

mod support;

use keyhog_core::{Chunk, Source, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};
// The whole file is `#![cfg(any(azure, gcs, s3))]` and all three providers'
// tests below assert skip-count deltas, so these are used under every enabled
// variant, the import must NOT be narrowed to `azure` alone (that made
// `--features s3` / `gcs` fail with `skip_counts`/`SkipCounts`/`SourceLimits`
// not in scope).
use keyhog_sources::{skip_counts, SkipCounts, SourceLimits};
use std::sync::{Mutex, MutexGuard};
use support::split_chunk_results;

const BUCKET: &str = "regression-bucket";
static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn counter_guard() -> MutexGuard<'static, ()> {
    // These httpmock tests point the cloud endpoint at 127.0.0.1, which the
    // default cloud SSRF endpoint screen now refuses. Opt into the loud,
    // default-off allowance for the lifetime of this (separate) test binary 
    // set while holding COUNTER_LOCK so it can never race a parallel test.
    let guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
}

fn assert_one_unreadable_listing_error(
    rows: &[Result<Chunk, SourceError>],
    before_unreadable: usize,
    source: &str,
    item_plural: &str,
) {
    let (chunks, errors) = split_chunk_results(rows);
    assert_eq!(
        chunks.len(),
        0,
        "a failed {source} listing must not claim scanned chunks"
    );
    assert_eq!(
        errors.len(),
        1,
        "a failed {source} listing must surface one SourceError row"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("source listing failed")
            && error.contains(&format!("{item_plural} were not scanned")),
        "{source} listing error must describe the unscanned source coverage gap, got {error}"
    );
    let after = skip_counts();
    assert_eq!(
        after.unreadable - before_unreadable,
        1,
        "{source} listing failure must bump SKIPPED_UNREADABLE exactly once"
    );
}

fn listing_limits(max_response_bytes: usize) -> SourceLimits {
    let mut limits = SourceLimits::default();
    limits.web_response_bytes = max_response_bytes;
    limits
}

fn assert_one_oversized_listing_error(
    rows: &[Result<Chunk, SourceError>],
    before: SkipCounts,
    source: &str,
    item_plural: &str,
    cap: usize,
) {
    let (chunks, errors) = split_chunk_results(rows);
    assert_eq!(
        chunks.len(),
        0,
        "an oversized {source} listing must not claim scanned chunks"
    );
    assert_eq!(
        errors.len(),
        1,
        "an oversized {source} listing must surface one SourceError row"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("source listing failed")
            && error.contains("listing response")
            && error.contains("web_response_bytes")
            && error.contains(&cap.to_string())
            && error.contains(&format!("{item_plural} were not scanned")),
        "{source} oversized listing error must describe the cap and unscanned coverage, got {error}"
    );
    let after = skip_counts();
    assert_eq!(
        after.over_max_size,
        before.over_max_size + 1,
        "{source} oversized listing must bump SKIPPED_OVER_MAX_SIZE exactly once"
    );
    assert_eq!(
        after.unreadable, before.unreadable,
        "{source} oversized listing must not be mislabeled unreadable"
    );
}

#[cfg(feature = "s3")]
struct RestoreS3Env {
    access_key: Option<std::ffi::OsString>,
    secret_key: Option<std::ffi::OsString>,
    session_token: Option<std::ffi::OsString>,
}

#[cfg(feature = "s3")]
impl RestoreS3Env {
    fn capture() -> Self {
        Self {
            access_key: std::env::var_os("AWS_ACCESS_KEY_ID"),
            secret_key: std::env::var_os("AWS_SECRET_ACCESS_KEY"),
            session_token: std::env::var_os("AWS_SESSION_TOKEN"),
        }
    }
}

#[cfg(feature = "s3")]
impl Drop for RestoreS3Env {
    fn drop(&mut self) {
        unsafe {
            match &self.access_key {
                Some(value) => std::env::set_var("AWS_ACCESS_KEY_ID", value),
                None => std::env::remove_var("AWS_ACCESS_KEY_ID"),
            }
            match &self.secret_key {
                Some(value) => std::env::set_var("AWS_SECRET_ACCESS_KEY", value),
                None => std::env::remove_var("AWS_SECRET_ACCESS_KEY"),
            }
            match &self.session_token {
                Some(value) => std::env::set_var("AWS_SESSION_TOKEN", value),
                None => std::env::remove_var("AWS_SESSION_TOKEN"),
            }
        }
    }
}

#[cfg(feature = "gcs")]
struct RestoreGcsEnv {
    google: Option<std::ffi::OsString>,
    gcs: Option<std::ffi::OsString>,
}

#[cfg(feature = "gcs")]
impl RestoreGcsEnv {
    fn capture() -> Self {
        Self {
            google: std::env::var_os("GOOGLE_OAUTH_ACCESS_TOKEN"),
            gcs: std::env::var_os("GCS_BEARER_TOKEN"),
        }
    }
}

#[cfg(feature = "gcs")]
impl Drop for RestoreGcsEnv {
    fn drop(&mut self) {
        unsafe {
            match &self.google {
                Some(value) => std::env::set_var("GOOGLE_OAUTH_ACCESS_TOKEN", value),
                None => std::env::remove_var("GOOGLE_OAUTH_ACCESS_TOKEN"),
            }
            match &self.gcs {
                Some(value) => std::env::set_var("GCS_BEARER_TOKEN", value),
                None => std::env::remove_var("GCS_BEARER_TOKEN"),
            }
        }
    }
}

#[cfg(feature = "s3")]
#[test]
fn s3_custom_endpoint_with_ambient_credentials_fails_before_anonymous_listing() {
    let _guard = counter_guard();
    let _restore = RestoreS3Env::capture();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "AKIAQYLPMN5HFIQR7XYA");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "synthetic-secret");
        std::env::remove_var("AWS_SESSION_TOKEN");
    }

    let server = httpmock::MockServer::start();
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(200).body("");
    });

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert_eq!(chunks.len(), 0, "the refused scan must not yield chunks");
    assert_eq!(errors.len(), 1, "the refused scan must surface one error");
    let error = errors[0].to_string();
    assert!(
        error.contains("AWS credentials are present")
            && error.contains("refusing to run anonymously"),
        "S3 custom endpoint credential refusal must be explicit, got {error}"
    );
    assert_eq!(
        list.calls(),
        0,
        "S3 must fail before issuing an anonymous listing request"
    );
    assert_eq!(
        skip_counts(),
        before,
        "credential policy refusals are config errors, not scan coverage skips"
    );
}

#[cfg(feature = "s3")]
#[test]
fn s3_partial_ambient_access_key_fails_before_unsigned_listing() {
    let _guard = counter_guard();
    let _restore = RestoreS3Env::capture();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "AKIAQYLPMN5HFIQR7XYA");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_SESSION_TOKEN");
    }

    let rows: Vec<_> = keyhog_sources::S3Source::new(BUCKET).chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert_eq!(chunks.len(), 0, "the refused scan must not yield chunks");
    assert_eq!(errors.len(), 1, "the refused scan must surface one error");
    let error = errors[0].to_string();
    assert!(
        error.contains("AWS_ACCESS_KEY_ID is set")
            && error.contains("AWS_SECRET_ACCESS_KEY is missing")
            && error.contains("refusing to run unsigned"),
        "partial S3 env auth must be explicit, got {error}"
    );
    assert_eq!(
        skip_counts(),
        before,
        "credential policy refusals are config errors, not scan coverage skips"
    );
}

#[cfg(feature = "s3")]
#[test]
fn s3_partial_ambient_secret_key_fails_before_unsigned_listing() {
    let _guard = counter_guard();
    let _restore = RestoreS3Env::capture();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    unsafe {
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "synthetic-secret");
        std::env::remove_var("AWS_SESSION_TOKEN");
    }

    let rows: Vec<_> = keyhog_sources::S3Source::new(BUCKET).chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert_eq!(chunks.len(), 0, "the refused scan must not yield chunks");
    assert_eq!(errors.len(), 1, "the refused scan must surface one error");
    let error = errors[0].to_string();
    assert!(
        error.contains("AWS_SECRET_ACCESS_KEY is set")
            && error.contains("AWS_ACCESS_KEY_ID is missing")
            && error.contains("refusing to run unsigned"),
        "partial S3 env auth must be explicit, got {error}"
    );
    assert_eq!(
        skip_counts(),
        before,
        "credential policy refusals are config errors, not scan coverage skips"
    );
}

#[cfg(feature = "s3")]
#[test]
fn s3_non_success_listing_is_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts().unreadable;

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(503).body("unavailable");
    });

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    assert_one_unreadable_listing_error(&rows, before, "S3", "objects");
}

#[cfg(feature = "s3")]
#[test]
fn s3_malformed_listing_is_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts().unreadable;

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(200)
            .header("content-type", "application/xml")
            .body("<ListBucketResult><Contents>");
    });

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    assert_one_unreadable_listing_error(&rows, before, "S3", "objects");
}

#[cfg(feature = "s3")]
#[test]
fn s3_oversized_listing_body_is_counted_and_stops_before_object_fetch() {
    let _guard = counter_guard();
    let _restore = RestoreS3Env::capture();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    unsafe {
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_SESSION_TOKEN");
    }

    let cap = 32;
    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(200)
            .header("content-type", "application/xml")
            .body("<ListBucketResult>".repeat(8));
    });
    let object = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/secret.txt");
        then.status(200).body("secret");
    });

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint_and_limits(BUCKET, server.url(""), listing_limits(cap))
        .chunks()
        .collect();
    assert_one_oversized_listing_error(&rows, before, "S3", "objects", cap);
    assert_eq!(
        object.calls(),
        0,
        "S3 must not fetch objects after an oversized listing body"
    );
}

#[cfg(feature = "gcs")]
#[test]
fn gcs_custom_endpoint_with_ambient_token_fails_before_anonymous_listing() {
    let _guard = counter_guard();
    let _restore = RestoreGcsEnv::capture();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    unsafe {
        std::env::set_var("GOOGLE_OAUTH_ACCESS_TOKEN", "synthetic-token");
        std::env::remove_var("GCS_BEARER_TOKEN");
    }

    let server = httpmock::MockServer::start();
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200).body(r#"{"items":[]}"#);
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert_eq!(chunks.len(), 0, "the refused scan must not yield chunks");
    assert_eq!(errors.len(), 1, "the refused scan must surface one error");
    let error = errors[0].to_string();
    assert!(
        error.contains("GOOGLE_OAUTH_ACCESS_TOKEN is present")
            && error.contains("refusing to run anonymously"),
        "GCS custom endpoint credential refusal must be explicit, got {error}"
    );
    assert_eq!(
        list.calls(),
        0,
        "GCS must fail before issuing an anonymous listing request"
    );
    assert_eq!(
        skip_counts(),
        before,
        "credential policy refusals are config errors, not scan coverage skips"
    );
}

#[cfg(feature = "gcs")]
#[test]
fn gcs_non_success_listing_is_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts().unreadable;

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(503).body("unavailable");
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    assert_one_unreadable_listing_error(&rows, before, "GCS", "objects");
}

#[cfg(feature = "gcs")]
#[test]
fn gcs_malformed_listing_is_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts().unreadable;

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"items":["#);
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    assert_one_unreadable_listing_error(&rows, before, "GCS", "objects");
}

#[cfg(feature = "gcs")]
#[test]
fn gcs_oversized_listing_body_is_counted_and_stops_before_object_fetch() {
    let _guard = counter_guard();
    let _restore = RestoreGcsEnv::capture();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    unsafe {
        std::env::remove_var("GOOGLE_OAUTH_ACCESS_TOKEN");
        std::env::remove_var("GCS_BEARER_TOKEN");
    }

    let cap = 32;
    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(r#"{{"items":[],"padding":"{}"}}"#, "x".repeat(cap)));
    });
    let object = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/secret.txt"));
        then.status(200).body("secret");
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint_and_limits(BUCKET, server.url(""), listing_limits(cap))
        .chunks()
        .collect();
    assert_one_oversized_listing_error(&rows, before, "GCS", "objects", cap);
    assert_eq!(
        object.calls(),
        0,
        "GCS must not fetch objects after an oversized listing body"
    );
}

#[cfg(feature = "azure")]
fn container_url(server: &httpmock::MockServer) -> String {
    format!("{}/container?sv=2024-11-04&sig=regression", server.url(""))
}

#[cfg(feature = "azure")]
#[test]
fn azure_non_success_listing_is_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts().unreadable;

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container")
            .query_param("sv", "2024-11-04")
            .query_param("sig", "regression")
            .query_param("restype", "container")
            .query_param("comp", "list");
        then.status(503).body("unavailable");
    });

    let rows: Vec<_> = TestApi
        .azure_blob_source(container_url(&server))
        .chunks()
        .collect();
    assert_one_unreadable_listing_error(&rows, before, "Azure Blob", "blobs");
}

#[cfg(feature = "azure")]
#[test]
fn azure_malformed_listing_is_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts().unreadable;

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
            .body("<EnumerationResults><Blobs>");
    });

    let rows: Vec<_> = TestApi
        .azure_blob_source(container_url(&server))
        .chunks()
        .collect();
    assert_one_unreadable_listing_error(&rows, before, "Azure Blob", "blobs");
}

#[cfg(feature = "azure")]
#[test]
fn azure_oversized_listing_body_is_counted_and_stops_before_blob_fetch() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let cap = 32;
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
            .body("<EnumerationResults>".repeat(8));
    });
    let blob = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/container/secret.txt");
        then.status(200).body("secret");
    });

    let rows: Vec<_> = TestApi
        .azure_blob_source_with_limits(container_url(&server), listing_limits(cap))
        .chunks()
        .collect();
    assert_one_oversized_listing_error(&rows, before, "Azure Blob", "blobs", cap);
    assert_eq!(
        blob.calls(),
        0,
        "Azure Blob must not fetch blobs after an oversized listing body"
    );
}
