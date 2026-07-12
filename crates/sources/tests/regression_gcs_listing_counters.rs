#![cfg(feature = "gcs")]

//! GCS listing-coverage counter accounting.
//!
//! Every object listed by the GCS JSON API must land in exactly one bucket:
//! scanned (a chunk), deliberately dropped (zero-size => `Ok(None)`, no chunk,
//! no counter), or refused with exactly ONE typed skip-counter bump and one
//! error row. These regressions pin the *exact* per-category counts so a future
//! refactor cannot double-count a drop, miss a listing failure, or let the
//! object total drift. Sibling of `regression_gcs_object_drops_counted.rs`.

mod support;

use keyhog_core::Source;
use keyhog_sources::skip_counts;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard};
use support::split_chunk_results;

const BUCKET: &str = "regression-bucket";
static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn counter_guard() -> MutexGuard<'static, ()> {
    // These httpmock tests point the cloud endpoint at 127.0.0.1, which the
    // default cloud SSRF endpoint screen refuses. Opt into the loud, default-off
    // allowance for the lifetime of this (separate) test binary — set while
    // holding COUNTER_LOCK so it can never race a parallel test.
    let guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
}

fn object(name: &str, size: u64) -> String {
    format!(r#"{{"name":"{name}","size":"{size}"}}"#)
}

fn object_unsized(name: &str) -> String {
    format!(r#"{{"name":"{name}"}}"#)
}

fn listing(objects: &str) -> String {
    format!(r#"{{"items":[{objects}]}}"#)
}

fn listing_with_token(objects: &str, token: &str) -> String {
    format!(r#"{{"items":[{objects}],"nextPageToken":"{token}"}}"#)
}

fn mock_listing(server: &httpmock::MockServer, body: String) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(body);
    })
}

// --- zero-size drops: no chunk, no GET, no counter -------------------------

#[test]
fn zero_size_object_is_dropped_without_get_and_uncounted() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = mock_listing(&server, listing(&object("empty.txt", 0)));
    let object_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/empty.txt"));
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();

    assert_eq!(
        rows.len(),
        0,
        "a zero-byte GCS object must yield neither a chunk nor an error row"
    );
    assert_eq!(
        object_get.calls(),
        0,
        "a zero-byte GCS object must not trigger a media GET"
    );
    let after = skip_counts();
    assert_eq!(
        after, before,
        "a deliberately dropped empty object must not touch any skip counter"
    );
}

#[test]
fn zero_size_object_alongside_text_scans_only_the_text_object() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = mock_listing(
        &server,
        listing(&format!(
            "{},{}",
            object("empty.txt", 0),
            object("config.txt", 40)
        )),
    );
    let empty_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/empty.txt"));
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });
    let _config_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/config.txt"))
            .query_param("alt", "media");
        then.status(200)
            .header("content-type", "text/plain")
            .body("aws_key=AKIAQYLPMN5HFIQR7XYA\n"); // keyhog:ignore detector=aws-access-key
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 1, "only the non-empty text object should scan");
    assert_eq!(errors.len(), 0, "neither listed object is a coverage gap");
    assert_eq!(
        ok[0].metadata.path.as_deref(),
        Some("gs://regression-bucket/config.txt")
    );
    assert_eq!(
        empty_get.calls(),
        0,
        "the empty object must still be dropped before its GET"
    );
    let after = skip_counts();
    assert_eq!(
        after, before,
        "one scanned + one dropped object must leave every skip counter untouched"
    );
}

// --- binary-extension drops: one SKIPPED_BINARY per object, no GET ----------

#[test]
fn single_binary_extension_object_bumps_binary_exactly_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = mock_listing(&server, listing(&object("bundle.zip", 512)));
    let object_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/bundle.zip"));
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 0, "a .zip object is not scanned as text");
    assert_eq!(
        errors.len(),
        1,
        "exactly one refusal row for one .zip object"
    );
    assert!(
        errors[0]
            .to_string()
            .contains("extension is treated as binary/container content"),
        "error must name the binary-extension refusal, got {}",
        errors[0]
    );

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "one binary-extension object must bump SKIPPED_BINARY exactly once"
    );
    assert_eq!(
        after.unreadable, before.unreadable,
        "a binary-extension drop must not be mislabeled unreadable"
    );
    assert_eq!(
        after.over_max_size, before.over_max_size,
        "a binary-extension drop must not be mislabeled over-max-size"
    );
    assert_eq!(
        object_get.calls(),
        0,
        "a binary-extension object must never be fetched"
    );
}

#[test]
fn three_binary_extension_objects_each_bump_binary_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let exts = ["zip", "tar", "gz"];
    let server = httpmock::MockServer::start();
    let objects = exts
        .iter()
        .map(|ext| object(&format!("archive.{ext}"), 256))
        .collect::<Vec<_>>()
        .join(",");
    let _list = mock_listing(&server, listing(&objects));
    let gets: Vec<_> = exts
        .iter()
        .map(|ext| {
            server.mock(|when, then| {
                when.method(httpmock::Method::GET)
                    .path(format!("/storage/v1/b/{BUCKET}/o/archive.{ext}"));
                then.status(200).body("SHOULD_NOT_BE_FETCHED");
            })
        })
        .collect();

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 0, "no binary-extension object is scanned");
    assert_eq!(errors.len(), 3, "one refusal row per binary object");

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        3,
        "three binary-extension objects must bump SKIPPED_BINARY exactly three times"
    );
    assert_eq!(
        after.total() - before.total(),
        3,
        "the whole-file skip total must grow by exactly the three binary drops"
    );
    for get in gets {
        assert_eq!(get.calls(), 0, "no binary-extension object may be fetched");
    }
}

// --- oversized drops: one SKIPPED_OVER_MAX_SIZE per object, no GET ----------

#[test]
fn three_oversized_objects_each_bump_over_max_size_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();
    let cap = keyhog_sources::SourceLimits::default().gcs_object_bytes;

    let names = ["huge-a.txt", "huge-b.txt", "huge-c.txt"];
    let server = httpmock::MockServer::start();
    let objects = names
        .iter()
        .map(|name| object(name, cap + 1))
        .collect::<Vec<_>>()
        .join(",");
    let _list = mock_listing(&server, listing(&objects));
    let gets: Vec<_> = names
        .iter()
        .map(|name| {
            server.mock(|when, then| {
                when.method(httpmock::Method::GET)
                    .path(format!("/storage/v1/b/{BUCKET}/o/{name}"));
                then.status(200).body("SHOULD_NOT_BE_FETCHED");
            })
        })
        .collect();

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 0, "no over-cap object is scanned");
    assert_eq!(errors.len(), 3, "one refusal row per over-cap object");
    for error in &errors {
        assert!(
            error
                .to_string()
                .contains("exceeds the per-object byte cap"),
            "error must name the over-cap refusal, got {error}"
        );
    }

    let after = skip_counts();
    assert_eq!(
        after.over_max_size - before.over_max_size,
        3,
        "three over-cap objects must bump SKIPPED_OVER_MAX_SIZE exactly three times"
    );
    assert_eq!(
        after.binary, before.binary,
        "an over-cap drop must not be mislabeled binary"
    );
    for get in gets {
        assert_eq!(
            get.calls(),
            0,
            "an over-cap object must be refused from listed size before any GET"
        );
    }
}

// --- unreadable GETs: one SKIPPED_UNREADABLE per failed object --------------

#[test]
fn three_non_success_gets_each_bump_unreadable_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let names = ["deny-a.txt", "deny-b.txt", "deny-c.txt"];
    let server = httpmock::MockServer::start();
    let objects = names
        .iter()
        .map(|name| object(name, 32))
        .collect::<Vec<_>>()
        .join(",");
    let _list = mock_listing(&server, listing(&objects));
    for name in names {
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/storage/v1/b/{BUCKET}/o/{name}"))
                .query_param("alt", "media");
            then.status(403).body("AccessDenied");
        });
    }

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 0, "no forbidden object is scanned");
    assert_eq!(errors.len(), 3, "one error row per forbidden object");
    for error in &errors {
        assert!(
            error.to_string().contains("GET returned 403"),
            "error must name the 403 refusal, got {error}"
        );
    }

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        3,
        "three forbidden GETs must bump SKIPPED_UNREADABLE exactly three times"
    );
}

// --- listing failures each count exactly one unreadable --------------------

#[test]
fn listing_non_success_counts_exactly_one_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

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
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 0, "a failed listing yields no scanned chunks");
    assert_eq!(errors.len(), 1, "a failed listing surfaces one error row");
    assert!(
        errors[0].to_string().contains("source listing failed")
            && errors[0].to_string().contains("objects were not scanned"),
        "listing error must describe the unscanned coverage gap, got {}",
        errors[0]
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "a non-success listing must bump SKIPPED_UNREADABLE exactly once"
    );
    assert_eq!(
        after.over_max_size, before.over_max_size,
        "a listing transport/status failure is not an over-max-size event"
    );
}

#[test]
fn malformed_listing_json_counts_exactly_one_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

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
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 0, "a malformed listing yields no chunks");
    assert_eq!(
        errors.len(),
        1,
        "a malformed listing surfaces one error row"
    );
    assert!(
        errors[0]
            .to_string()
            .contains("failed to parse listing response"),
        "listing error must name the parse failure, got {}",
        errors[0]
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "a malformed listing body must bump SKIPPED_UNREADABLE exactly once"
    );
}

// --- object total is exact across a mixed listing --------------------------

#[test]
fn mixed_listing_object_total_is_exact() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();
    let cap = keyhog_sources::SourceLimits::default().gcs_object_bytes;

    // Five listed objects, one per outcome:
    //   scan.txt   -> scanned (1 chunk)
    //   empty.txt  -> dropped (Ok(None), no chunk, no counter)
    //   photo.zip  -> SKIPPED_BINARY
    //   huge.txt   -> SKIPPED_OVER_MAX_SIZE
    //   denied.txt -> SKIPPED_UNREADABLE
    let server = httpmock::MockServer::start();
    let body = listing(
        &[
            object("scan.txt", 40),
            object("empty.txt", 0),
            object("photo.zip", 100),
            object("huge.txt", cap + 1),
            object("denied.txt", 32),
        ]
        .join(","),
    );
    let _list = mock_listing(&server, body);
    let _scan_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/scan.txt"))
            .query_param("alt", "media");
        then.status(200)
            .header("content-type", "text/plain")
            .body("token=AKIAQYLPMN5HFIQR7XYA\n"); // keyhog:ignore detector=aws-access-key
    });
    let _denied_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/denied.txt"))
            .query_param("alt", "media");
        then.status(403).body("AccessDenied");
    });
    let zip_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/photo.zip"));
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });
    let huge_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/huge.txt"));
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 1, "exactly one text object is scanned");
    assert_eq!(
        ok[0].metadata.path.as_deref(),
        Some("gs://regression-bucket/scan.txt")
    );
    assert_eq!(
        errors.len(),
        3,
        "three of five objects are refused coverage"
    );

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "exactly one binary drop across the mixed listing"
    );
    assert_eq!(
        after.over_max_size - before.over_max_size,
        1,
        "exactly one over-max-size drop across the mixed listing"
    );
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "exactly one unreadable drop across the mixed listing"
    );
    assert_eq!(
        after.source_truncated, before.source_truncated,
        "a fully-listed page is never a truncated source"
    );
    // 5 listed = 1 scanned + 1 dropped + 3 refused; refusals total exactly 3.
    assert_eq!(
        after.total() - before.total(),
        3,
        "the whole-file skip total must equal the three refused objects exactly"
    );
    assert_eq!(
        zip_get.calls(),
        0,
        "the binary-extension object must not be fetched"
    );
    assert_eq!(
        huge_get.calls(),
        0,
        "the over-cap object must not be fetched"
    );
}

#[test]
fn all_text_objects_scanned_object_total_is_exact() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let names = ["one.txt", "two.txt", "three.txt", "four.txt"];
    let server = httpmock::MockServer::start();
    let objects = names
        .iter()
        .map(|name| object(name, 24))
        .collect::<Vec<_>>()
        .join(",");
    let _list = mock_listing(&server, listing(&objects));
    for name in names {
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/storage/v1/b/{BUCKET}/o/{name}"))
                .query_param("alt", "media");
            then.status(200)
                .header("content-type", "text/plain")
                .body(format!("body of {name}\n"));
        });
    }

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 4, "all four text objects must be scanned");
    assert_eq!(errors.len(), 0, "no coverage gap for four readable objects");

    let paths: BTreeSet<String> = ok
        .iter()
        .filter_map(|chunk| chunk.metadata.path.as_deref().map(String::from))
        .collect();
    let expected: BTreeSet<String> = names
        .iter()
        .map(|name| format!("gs://regression-bucket/{name}"))
        .collect();
    assert_eq!(
        paths, expected,
        "every listed object key must be scanned once"
    );

    let after = skip_counts();
    assert_eq!(
        after, before,
        "a fully readable listing must leave every skip counter untouched"
    );
}

#[test]
fn paginated_listing_scans_every_page_object_total_is_exact() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    // First page carries a meaningful nextPageToken; second page has none.
    let _page1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json")
            .query_param_missing("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(listing_with_token(&object("p1.txt", 16), "PAGE2"));
    });
    let _page2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json")
            .query_param("pageToken", "PAGE2");
        then.status(200)
            .header("content-type", "application/json")
            .body(listing(&object("p2.txt", 16)));
    });
    for name in ["p1.txt", "p2.txt"] {
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/storage/v1/b/{BUCKET}/o/{name}"))
                .query_param("alt", "media");
            then.status(200)
                .header("content-type", "text/plain")
                .body(format!("page body {name}\n"));
        });
    }

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 2, "both paginated objects must be scanned");
    assert_eq!(errors.len(), 0, "no coverage gap across two clean pages");

    let paths: BTreeSet<String> = ok
        .iter()
        .filter_map(|chunk| chunk.metadata.path.as_deref().map(String::from))
        .collect();
    let expected: BTreeSet<String> = ["p1.txt", "p2.txt"]
        .iter()
        .map(|name| format!("gs://regression-bucket/{name}"))
        .collect();
    assert_eq!(
        paths, expected,
        "the object total across both pages must be exactly p1 + p2"
    );

    let after = skip_counts();
    assert_eq!(after, before, "clean pagination must not record any skip");
}

// --- negative twin: a scanned object bumps no partial-coverage counter ------

#[test]
fn scanned_object_bumps_no_partial_coverage_counters_and_carries_listed_size() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = mock_listing(&server, listing(&object("readable.txt", 55)));
    let _get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/readable.txt"))
            .query_param("alt", "media");
        then.status(200)
            .header("content-type", "text/plain")
            .body("plain readable body without any secret\n");
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 1, "the readable object must scan");
    assert_eq!(errors.len(), 0, "a readable object is not a coverage gap");
    assert_eq!(
        ok[0].metadata.size_bytes,
        Some(55),
        "the chunk must carry the listed object size verbatim"
    );

    let after = skip_counts();
    assert_eq!(
        after.binary, before.binary,
        "no binary skip for a text object"
    );
    assert_eq!(
        after.over_max_size, before.over_max_size,
        "no over-max-size skip for an in-cap object"
    );
    assert_eq!(
        after.unreadable, before.unreadable,
        "no unreadable skip for a 200 text object"
    );
    assert_eq!(
        after.source_truncated, before.source_truncated,
        "no source-truncated skip for a fully listed source"
    );
    assert_eq!(
        after.total(),
        before.total(),
        "the skip total must not move"
    );
}

// --- adversarial: an unparseable listed size errors without a skip bump -----

#[test]
fn unparseable_listed_size_errors_without_any_counter_bump() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    // A non-numeric `size` is a malformed listing entry: `size_bytes()` returns
    // a plain SourceError (config/parse error), NOT a coverage skip.
    let _list = mock_listing(
        &server,
        listing(r#"{"name":"bad.txt","size":"not-a-number"}"#),
    );
    let object_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/bad.txt"));
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 0, "a malformed size entry yields no chunk");
    assert_eq!(
        errors.len(),
        1,
        "a malformed size entry yields one error row"
    );
    assert!(
        errors[0]
            .to_string()
            .contains("failed to parse GCS object size for 'bad.txt'"),
        "error must name the unparseable size, got {}",
        errors[0]
    );

    let after = skip_counts();
    assert_eq!(
        after, before,
        "a size-parse error is not a coverage skip and must bump no counter"
    );
    assert_eq!(
        object_get.calls(),
        0,
        "a malformed listing entry must not trigger a media GET"
    );
}

// --- boundary: an unsized (no size field) text object is scanned ------------

#[test]
fn object_without_size_field_is_scanned_and_uncounted() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    // No `size` field => `size_bytes()` is Ok(None): not a zero-size drop, so the
    // object is fetched and, being small text, scanned. size_bytes on the chunk
    // is None because the listing never declared a size.
    let _list = mock_listing(&server, listing(&object_unsized("nosize.txt")));
    let get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/nosize.txt"))
            .query_param("alt", "media");
        then.status(200)
            .header("content-type", "text/plain")
            .body("body with no declared size\n");
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 1, "an unsized object must be fetched and scanned");
    assert_eq!(errors.len(), 0, "an unsized readable object is not a gap");
    assert_eq!(
        ok[0].metadata.size_bytes, None,
        "an unsized listing entry yields a None chunk size"
    );
    assert_eq!(
        get.calls(),
        1,
        "an unsized object must trigger exactly one media GET"
    );

    let after = skip_counts();
    assert_eq!(
        after, before,
        "scanning an unsized object must not touch any skip counter"
    );
}
