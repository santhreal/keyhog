//! LANE sources-deep Law-10 regression: an S3 object the source DROPS (over the
//! per-object byte cap, declared a binary content-type, or a body that fails the
//! UTF-8 decode the content-type promised) must be COUNTED in the shared
//! `skip_counts()` so end-of-scan coverage reflects the gap — never a silent
//! `tracing::debug!` + `return Ok(None)`.
//!
//! Before the fix `fetch_object_chunk` logged each of these drops at
//! `tracing::debug!` (invisible at default verbosity) and returned `Ok(None)`
//! WITHOUT bumping any counter, so an oversized / binary / mis-labelled object
//! read as full coverage: a "0 findings" S3 scan could not be distinguished from
//! "every object was actually scanned". The fix routes:
//!   * over-cap (listed size, Content-Length, or streamed body) -> SKIPPED_OVER_MAX_SIZE
//!   * binary content-type                                       -> SKIPPED_BINARY
//!   * text-labelled body that fails UTF-8                       -> SKIPPED_UNREADABLE
//! and upgrades every drop log from `debug!` to a loud `warn!`. This test pins
//! the exact counter deltas by driving the REAL `S3Source::chunks()` production
//! path (list -> per-object fetch -> skip) against an httpmock S3 endpoint.
//!
//! Own test binary: the `SKIPPED_*` counters are process-global atomics, so a
//! dedicated binary keeps the baseline from being polluted by the filesystem
//! tests that share them.

#![cfg(feature = "s3")]

use keyhog_core::Source;
use keyhog_sources::skip_counts;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::sync::{Mutex, MutexGuard};

const BUCKET: &str = "regression-bucket";
static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn counter_guard() -> MutexGuard<'static, ()> {
    COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One `<Contents>` block for a ListObjectsV2 body.
fn contents(key: &str, size: u64) -> String {
    format!("<Contents><Key>{key}</Key><Size>{size}</Size></Contents>")
}

/// Wrap object blocks into a non-truncated ListObjectsV2 result.
fn listing(objects: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{BUCKET}</Name>
  <IsTruncated>false</IsTruncated>
  {objects}
</ListBucketResult>"#
    )
}

fn truncated_listing(objects: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{BUCKET}</Name>
  <IsTruncated>true</IsTruncated>
  {objects}
</ListBucketResult>"#
    )
}

/// The per-object byte cap baked into `s3/mod.rs` (`MAX_S3_OBJECT_BYTES`).
const MAX_S3_OBJECT_BYTES: u64 = 10 * 1024 * 1024;

/// An over-cap object (listed `Size` beyond the per-object cap) is DROPPED before
/// any GET and counted as over-max-size, not silently skipped.
#[test]
fn oversized_listed_object_is_counted_over_max_size() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    // `is_probably_text` keys off the extension, so use `.txt` to make sure the
    // object reaches the size gate rather than the extension pre-filter.
    let body = listing(&contents("huge.txt", MAX_S3_OBJECT_BYTES + 1));
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(body);
    });
    // No object GET mock: the source must NOT issue one for an over-cap object.
    let object_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path_includes("huge.txt");
        then.status(200).body("PLACEHOLDER_SHOULD_NOT_BE_FETCHED");
    });

    let ok: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        ok.len(),
        0,
        "an over-cap object yields no scanned chunk; got {} chunk(s)",
        ok.len()
    );

    let after = skip_counts();
    assert_eq!(
        after.over_max_size - before.over_max_size,
        1,
        "the over-cap object MUST bump SKIPPED_OVER_MAX_SIZE exactly once (Law 10), \
         not silently vanish from coverage"
    );
    assert_eq!(
        object_get.calls(),
        0,
        "an over-cap object must be dropped from the listing BEFORE any GET is issued"
    );
}

/// A binary content-type object is DROPPED and counted as binary (the same
/// category the filesystem walker uses for binary-extension skips).
#[test]
fn binary_content_type_object_is_counted_binary() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    // Extension `.bin` is NOT in `is_probably_text`'s deny-list, so the object
    // reaches the GET and the content-type guard fires there (exercising the
    // production content-type skip path, not the extension pre-filter).
    let body = listing(&contents("payload.bin", 512));
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(body);
    });
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_includes("payload.bin");
        then.status(200)
            .header("content-type", "application/octet-stream")
            .body(vec![0u8; 512]);
    });

    let ok: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        ok.len(),
        0,
        "a binary content-type object yields no scanned chunk; got {} chunk(s)",
        ok.len()
    );

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "a binary content-type object MUST bump SKIPPED_BINARY exactly once (Law 10)"
    );
    assert_eq!(
        after.over_max_size - before.over_max_size,
        0,
        "a binary skip must NOT be miscounted as an over-size skip"
    );
}

/// Objects prefiltered by binary/container extension are dropped before GET and
/// must still be counted as binary coverage gaps.
#[test]
fn binary_extension_object_is_counted_binary_without_get() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let body = listing(&contents("bundle.zip", 512));
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(body);
    });
    let object_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_includes("bundle.zip");
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let ok: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(ok.len(), 0, "binary-extension object must not be scanned");

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "binary/container extension prefilter MUST bump SKIPPED_BINARY exactly once"
    );
    assert_eq!(
        object_get.calls(),
        0,
        "binary-extension object must be counted before any GET is issued"
    );
}

/// A body the server LABELS text but that fails UTF-8 decode is DROPPED and
/// counted as unreadable (an UNKNOWN, not clean coverage).
#[test]
fn non_utf8_text_labelled_object_is_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let body = listing(&contents("lies.txt", 4));
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(body);
    });
    // text/plain content-type but invalid UTF-8 bytes (lone 0xFF / 0xFE).
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path_includes("lies.txt");
        then.status(200)
            .header("content-type", "text/plain")
            .body(vec![0xFFu8, 0xFE, 0x00, 0x80]);
    });

    let ok: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        ok.len(),
        0,
        "a non-UTF-8 text-labelled object yields no scanned chunk; got {} chunk(s)",
        ok.len()
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "a text-labelled body that fails UTF-8 MUST bump SKIPPED_UNREADABLE exactly \
         once (Law 10): the server lied about the type and the object was NOT scanned"
    );
}

/// A listed object whose GET returns a non-success status is also an unreadable
/// coverage gap. Continuing with the rest of the page is fine; pretending the
/// object was clean is not.
#[test]
fn non_success_get_is_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let body = listing(&contents("forbidden.txt", 32));
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(body);
    });
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_includes("forbidden.txt");
        then.status(403).body("AccessDenied");
    });

    let ok: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        ok.len(),
        0,
        "a non-success S3 object GET yields no scanned chunk; got {} chunk(s)",
        ok.len()
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "a listed object whose GET fails MUST bump SKIPPED_UNREADABLE exactly once"
    );
    assert_eq!(
        after.binary - before.binary,
        0,
        "a failed GET is an unreadable source gap, not a binary skip"
    );
}

/// If the configured object cap cuts off a listing page, the bucket scan is
/// partial. The first object can still be scanned, but remaining listed objects
/// must be surfaced as source-level truncation.
#[test]
fn max_objects_limit_is_counted_source_truncated() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let body = listing(&format!(
        "{}{}",
        contents("first.txt", 16),
        contents("second.txt", 16)
    ));
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(body);
    });
    let _first = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_includes("first.txt");
        then.status(200)
            .header("content-type", "text/plain")
            .body("first object\n");
    });
    let second_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_includes("second.txt");
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let ok: Vec<_> = TestApi
        .s3_source_with_endpoint_max_objects(BUCKET, server.url(""), 1)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        ok.len(),
        1,
        "the allowed first object should still be scanned"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "max_objects truncation MUST bump SOURCE_TRUNCATED exactly once"
    );
    assert_eq!(
        second_get.calls(),
        0,
        "objects beyond the cap must not be fetched"
    );
}

/// A service response that says more objects exist but omits the continuation
/// token leaves the bucket only partially covered.
#[test]
fn truncated_listing_without_token_is_counted_source_truncated() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let body = truncated_listing(&contents("config.txt", 16));
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(body);
    });
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_includes("config.txt");
        then.status(200)
            .header("content-type", "text/plain")
            .body("config object\n");
    });

    let ok: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        ok.len(),
        1,
        "the visible page object should still be scanned"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "truncated S3 listing without continuation token MUST bump SOURCE_TRUNCATED"
    );
}

/// Positive twin: a genuine text object IS scanned and bumps NO skip counter, so
/// the skip-counting is specific to real drops and never inflates coverage gaps
/// for objects that were actually scanned.
#[test]
fn plain_text_object_is_scanned_and_not_counted_as_skipped() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let body = listing(&contents("config.txt", 40));
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(body);
    });
    // A real-shape AWS key so the scanned chunk has recognizable content.
    let object_body = "aws_key=AKIAQYLPMN5HFIQR7XYA\n"; // keyhog:ignore detector=aws-access-key (synthetic test fixture)
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_includes("config.txt");
        then.status(200)
            .header("content-type", "text/plain")
            .body(object_body);
    });

    let ok: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        ok.len(),
        1,
        "the one text object must produce exactly one chunk"
    );
    assert!(
        ok[0].data.as_ref().contains("AKIAQYLPMN5HFIQR7XYA"), // keyhog:ignore detector=aws-access-key (synthetic test fixture)
        "the scanned chunk must carry the object body verbatim; got {:?}",
        ok[0].data.as_ref()
    );
    assert_eq!(
        ok[0].metadata.path.as_deref(),
        Some("regression-bucket/config.txt"),
        "the chunk path must be bucket/key"
    );

    let after = skip_counts();
    assert_eq!(
        after.total(),
        before.total(),
        "a real text object must bump NO skip counter (it was fully scanned)"
    );
}
