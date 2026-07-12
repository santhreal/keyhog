//! LANE sources-deep regression: the S3 ListObjectsV2 pagination loop
//! (`collect_s3_chunks` in `s3/mod.rs`) must
//!   * walk every page — threading the previous page's `NextContinuationToken`
//!     (and the caller's `prefix`) into the next request — and yield the EXACT
//!     union object count across all pages, and
//!   * record each per-object coverage gap EXACTLY ONCE even when it is one
//!     object out of a multi-page listing (a skipped object bumps its counter
//!     by 1, never by 2 / never per page), and
//!   * count a listing-level failure (auth 403 / mid-pagination 5xx) as exactly
//!     one `SKIPPED_UNREADABLE` listing skip.
//!
//! These assertions drive the REAL `S3Source::chunks()` production path
//! (list -> continuation-token -> next list -> per-object fetch) against an
//! httpmock S3 endpoint, disambiguating the first page (`continuation-token`
//! absent) from later pages (`continuation-token` == the exact prior token) with
//! `query_param_missing` / `query_param`.
//!
//! Own test binary: the `SKIPPED_*` counters are process-global atomics, so a
//! dedicated binary + a `COUNTER_LOCK`-serialized asserting window keeps the
//! baseline from being polluted by sibling source tests that share them. Mirrors
//! the harness in `regression_s3_skipped_objects_counted.rs`.

#![cfg(feature = "s3")]

mod support;

use keyhog_core::Source;
use keyhog_sources::skip_counts;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::sync::{Mutex, MutexGuard};
use support::split_chunk_results;

const BUCKET: &str = "regression-bucket";
static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn counter_guard() -> MutexGuard<'static, ()> {
    // httpmock binds 127.0.0.1, which the cloud SSRF endpoint screen refuses by
    // default. Opt into the loud, default-off private-endpoint allowance for the
    // lifetime of this separate binary — set while holding COUNTER_LOCK so it
    // can never race a parallel test in this file.
    let guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
}

/// The per-object byte cap baked into the resolved `SourceLimits` (`s3_object_bytes`).
const MAX_S3_OBJECT_BYTES: u64 = 10 * 1024 * 1024;

/// One `<Contents>` block for a ListObjectsV2 body.
fn contents(key: &str, size: u64) -> String {
    format!("<Contents><Key>{key}</Key><Size>{size}</Size></Contents>")
}

/// A terminal (non-truncated) ListObjectsV2 page.
fn final_page(objects: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{BUCKET}</Name>
  <IsTruncated>false</IsTruncated>
  {objects}
</ListBucketResult>"#
    )
}

/// A truncated page carrying a concrete `NextContinuationToken` cursor.
fn truncated_page_with_token(objects: &str, token: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{BUCKET}</Name>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>{token}</NextContinuationToken>
  {objects}
</ListBucketResult>"#
    )
}

/// A truncated page whose `NextContinuationToken` element is present but empty —
/// the S3-compatible "final page echoed an empty cursor" shape that
/// `meaningful_continuation_token` normalizes to "exhausted".
fn truncated_page_empty_token(objects: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{BUCKET}</Name>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken></NextContinuationToken>
  {objects}
</ListBucketResult>"#
    )
}

/// A truncated page that omits the `NextContinuationToken` element entirely.
fn truncated_page_no_token(objects: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{BUCKET}</Name>
  <IsTruncated>true</IsTruncated>
  {objects}
</ListBucketResult>"#
    )
}

/// Register a text-object GET mock returning `body` as `text/plain`.
fn mock_text_object<'a>(
    server: &'a httpmock::MockServer,
    key: &'static str,
    body: &'static str,
) -> httpmock::Mock<'a> {
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path_includes(key);
        then.status(200)
            .header("content-type", "text/plain")
            .body(body);
    })
}

// ---------------------------------------------------------------------------
// Multi-page listing yields the EXACT union object count.
// ---------------------------------------------------------------------------

/// Baseline positive: a single non-truncated page with three text objects yields
/// exactly three chunks (bucket/key paths), and no page-2 request is made.
#[test]
fn single_page_three_text_objects_exact_count() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let body = final_page(&format!(
        "{}{}{}",
        contents("a.txt", 16),
        contents("b.txt", 16),
        contents("c.txt", 16)
    ));
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(body);
    });
    let _a = mock_text_object(&server, "a.txt", "alpha\n");
    let _b = mock_text_object(&server, "b.txt", "bravo\n");
    let _c = mock_text_object(&server, "c.txt", "charlie\n");

    let ok: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(
        ok.len(),
        3,
        "three text objects must yield exactly 3 chunks"
    );
    let mut paths: Vec<&str> = ok
        .iter()
        .map(|c| c.metadata.path.as_deref().unwrap())
        .collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        vec![
            "regression-bucket/a.txt",
            "regression-bucket/b.txt",
            "regression-bucket/c.txt"
        ]
    );
    assert_eq!(
        list.calls(),
        1,
        "a single page needs exactly one list request"
    );

    let after = skip_counts();
    assert_eq!(
        after.total(),
        before.total(),
        "fully-scanned text objects must not inflate any skip counter"
    );
    assert_eq!(after.source_truncated - before.source_truncated, 0);
}

/// A two-page listing (page 1 truncated with a token, page 2 terminal) yields the
/// exact union count of both pages' objects, and each page is listed once.
#[test]
fn two_page_listing_yields_exact_object_count() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let page1 = truncated_page_with_token(
        &format!("{}{}", contents("p1-a.txt", 16), contents("p1-b.txt", 16)),
        "CURSOR-PAGE-2",
    );
    let page2 = final_page(&contents("p2-a.txt", 16));

    let list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    let list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param("continuation-token", "CURSOR-PAGE-2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page2);
    });
    let _o1 = mock_text_object(&server, "p1-a.txt", "one\n");
    let _o2 = mock_text_object(&server, "p1-b.txt", "two\n");
    let _o3 = mock_text_object(&server, "p2-a.txt", "three\n");

    let ok: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(
        ok.len(),
        3,
        "2 objects on page 1 + 1 on page 2 must yield exactly 3 chunks"
    );
    assert_eq!(list1.calls(), 1, "page 1 must be listed exactly once");
    assert_eq!(list2.calls(), 1, "page 2 must be listed exactly once");

    let after = skip_counts();
    assert_eq!(
        after.total(),
        before.total(),
        "a clean two-page listing bumps no skip counter"
    );
    assert_eq!(after.source_truncated - before.source_truncated, 0);
}

/// A three-page listing (token, token, terminal) yields the exact union count and
/// lists each page exactly once — the continuation loop terminates on the final
/// non-truncated page.
#[test]
fn three_page_listing_yields_exact_object_count() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let page1 = truncated_page_with_token(
        &format!("{}{}", contents("g1-a.txt", 16), contents("g1-b.txt", 16)),
        "TOK-2",
    );
    let page2 = truncated_page_with_token(
        &format!("{}{}", contents("g2-a.txt", 16), contents("g2-b.txt", 16)),
        "TOK-3",
    );
    let page3 = final_page(&contents("g3-a.txt", 16));

    let list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    let list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param("continuation-token", "TOK-2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page2);
    });
    let list3 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param("continuation-token", "TOK-3");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page3);
    });
    for key in ["g1-a.txt", "g1-b.txt", "g2-a.txt", "g2-b.txt", "g3-a.txt"] {
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path_includes(key);
            then.status(200)
                .header("content-type", "text/plain")
                .body("payload\n");
        });
    }

    let ok: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(ok.len(), 5, "2 + 2 + 1 objects must yield exactly 5 chunks");
    assert_eq!(list1.calls(), 1);
    assert_eq!(list2.calls(), 1, "page 2 must be requested with TOK-2 once");
    assert_eq!(list3.calls(), 1, "page 3 must be requested with TOK-3 once");

    let after = skip_counts();
    assert_eq!(after.total(), before.total());
    assert_eq!(after.source_truncated - before.source_truncated, 0);
}

/// The `NextContinuationToken` from page 1 must be threaded VERBATIM as the
/// page-2 `continuation-token` query param: the page-2 mock only matches the
/// exact token, so a hit count of 1 proves the token was neither dropped nor
/// mangled.
#[test]
fn continuation_token_threaded_verbatim_to_second_page() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();

    let server = httpmock::MockServer::start();
    let token = "NextPage-Cursor-42";
    let page1 = truncated_page_with_token(&contents("v1.txt", 16), token);
    let page2 = final_page(&contents("v2.txt", 16));

    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    let list2_exact = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param("continuation-token", token);
        then.status(200)
            .header("content-type", "application/xml")
            .body(page2);
    });
    let _o1 = mock_text_object(&server, "v1.txt", "v1\n");
    let _o2 = mock_text_object(&server, "v2.txt", "v2\n");

    let ok: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(ok.len(), 2, "both pages' single objects must be scanned");
    assert_eq!(
        list2_exact.calls(),
        1,
        "page 2 must be listed exactly once with the verbatim continuation token"
    );
}

/// A zero-`Size` object listed across pages is dropped before any GET (S3 lists
/// zero-byte objects and "directory placeholder" keys), yields no chunk, and
/// bumps NO skip counter — the empty object is not a coverage gap. The two
/// non-empty text objects around it are still scanned, so the union count is 2.
#[test]
fn zero_size_object_across_pages_yields_no_chunk_and_no_skip() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let page1 = truncated_page_with_token(
        &format!("{}{}", contents("real1.txt", 16), contents("empty.txt", 0)),
        "ZERO-2",
    );
    let page2 = final_page(&contents("real2.txt", 16));

    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    let _list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param("continuation-token", "ZERO-2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page2);
    });
    let _o1 = mock_text_object(&server, "real1.txt", "r1\n");
    let _o2 = mock_text_object(&server, "real2.txt", "r2\n");
    // A GET for the zero-size object must never be issued.
    let empty_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_includes("empty.txt");
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 2, "only the two non-empty objects yield chunks");
    assert_eq!(
        errors.len(),
        0,
        "a zero-size object is not an error/coverage gap"
    );
    let mut paths: Vec<&str> = ok
        .iter()
        .map(|c| c.metadata.path.as_deref().unwrap())
        .collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        vec!["regression-bucket/real1.txt", "regression-bucket/real2.txt"]
    );
    assert_eq!(
        empty_get.calls(),
        0,
        "a zero-size object must be dropped before any GET is issued"
    );

    let after = skip_counts();
    assert_eq!(
        after.total(),
        before.total(),
        "a zero-size object bumps no whole-file skip counter"
    );
    assert_eq!(after.source_truncated - before.source_truncated, 0);
}

// ---------------------------------------------------------------------------
// Truncated-but-no-usable-cursor => SOURCE_TRUNCATED exactly once.
// ---------------------------------------------------------------------------

/// A truncated page whose `NextContinuationToken` is present-but-empty is
/// normalized to "exhausted": the visible object is scanned, the gap is surfaced
/// as SOURCE_TRUNCATED exactly once, and NO page-2 request is made.
#[test]
fn empty_continuation_token_counts_source_truncated_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let page1 = truncated_page_empty_token(&contents("cfg.txt", 16));
    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    let _obj = mock_text_object(&server, "cfg.txt", "cfg\n");
    // A page-2 request (with ANY continuation token) must never be issued.
    let page2_probe = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_exists("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(final_page(&contents("should-not-be-listed.txt", 16)));
    });

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 1, "the visible page object must still be scanned");
    assert_eq!(
        errors.len(),
        1,
        "an empty continuation token on a truncated listing surfaces one error"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("source scan was truncated")
            && err.contains("remaining objects were not scanned"),
        "error should describe partial S3 coverage, got {err}"
    );
    assert_eq!(
        page2_probe.calls(),
        0,
        "an empty continuation token must NOT trigger a page-2 listing (no restart loop)"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "empty continuation token MUST bump SOURCE_TRUNCATED exactly once"
    );
    assert_eq!(
        after.unreadable - before.unreadable,
        0,
        "a normalized empty cursor is a source truncation, not an unreadable listing"
    );
}

/// A truncated page that omits the token element entirely is also SOURCE_TRUNCATED
/// exactly once (distinct XML shape, same coverage semantics).
#[test]
fn truncated_listing_missing_token_counts_source_truncated_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let page1 = truncated_page_no_token(&contents("data.txt", 16));
    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    let _obj = mock_text_object(&server, "data.txt", "data\n");

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 1, "the visible object must be scanned");
    assert_eq!(errors.len(), 1, "missing token surfaces exactly one error");

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "a truncated listing without a token MUST bump SOURCE_TRUNCATED exactly once"
    );
}

/// The `max_objects` cap stops pagination BEFORE the second-page listing is ever
/// requested: after the capped first page, the loop records SOURCE_TRUNCATED once
/// and does not follow the continuation token.
#[test]
fn max_objects_cap_stops_before_second_page_listing() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let page1 = truncated_page_with_token(&contents("only.txt", 16), "CAP-2");
    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    let list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param("continuation-token", "CAP-2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(final_page(&contents("beyond.txt", 16)));
    });
    let _obj = mock_text_object(&server, "only.txt", "only\n");

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint_max_objects(BUCKET, server.url(""), 1)
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 1, "exactly the one allowed object is scanned");
    assert_eq!(errors.len(), 1, "the cap surfaces one truncation error");
    assert_eq!(
        list2.calls(),
        0,
        "the object cap must stop pagination before the page-2 listing is issued"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "max_objects truncation MUST bump SOURCE_TRUNCATED exactly once"
    );
}

// ---------------------------------------------------------------------------
// A skipped object bumps its coverage counter by EXACTLY 1 (not per page / not 2).
// ---------------------------------------------------------------------------

/// A single binary-extension object living among two pages of text objects is
/// counted as one binary coverage gap — not once per page, not twice.
#[test]
fn skipped_binary_extension_object_across_pages_counts_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    // Page 1 carries the binary-extension object plus one text object; page 2 has
    // one more text object. Only ONE object is a coverage gap.
    let page1 = truncated_page_with_token(
        &format!(
            "{}{}",
            contents("good1.txt", 16),
            contents("bundle.zip", 512)
        ),
        "BIN-2",
    );
    let page2 = final_page(&contents("good2.txt", 16));

    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    let _list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param("continuation-token", "BIN-2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page2);
    });
    let _o1 = mock_text_object(&server, "good1.txt", "g1\n");
    let _o2 = mock_text_object(&server, "good2.txt", "g2\n");
    // The .zip must be prefiltered before any GET is issued.
    let zip_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_includes("bundle.zip");
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(
        ok.len(),
        2,
        "both text objects (one per page) must be scanned"
    );
    assert_eq!(
        errors.len(),
        1,
        "exactly one binary-extension gap error row"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("extension is treated as binary/container content")
            && err.contains("object was not scanned"),
        "error should name the unscanned binary-extension object, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "one binary object across a multi-page listing MUST bump SKIPPED_BINARY by exactly 1, not 2"
    );
    assert_eq!(
        after.over_max_size - before.over_max_size,
        0,
        "a binary skip must not be miscounted elsewhere"
    );
    assert_eq!(after.unreadable - before.unreadable, 0);
    assert_eq!(
        zip_get.calls(),
        0,
        "the binary-extension object must be dropped before any GET"
    );
}

/// An over-cap object listed on the SECOND page is counted as over-max-size
/// exactly once and never fetched; the first-page text object is still scanned.
#[test]
fn oversized_object_on_second_page_counts_over_max_size_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let page1 = truncated_page_with_token(&contents("small.txt", 16), "BIG-2");
    let page2 = final_page(&contents("huge.txt", MAX_S3_OBJECT_BYTES + 1));

    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    let _list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param("continuation-token", "BIG-2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page2);
    });
    let _o1 = mock_text_object(&server, "small.txt", "small\n");
    let huge_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path_includes("huge.txt");
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(
        ok.len(),
        1,
        "the first-page text object must still be scanned"
    );
    assert_eq!(errors.len(), 1, "the over-cap object emits one error row");
    let err = errors[0].to_string();
    assert!(
        err.contains("listed size")
            && err.contains("exceeds the per-object byte cap")
            && err.contains("object was not scanned"),
        "error should name the unscanned over-cap object, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.over_max_size - before.over_max_size,
        1,
        "the page-2 over-cap object MUST bump SKIPPED_OVER_MAX_SIZE by exactly 1"
    );
    assert_eq!(after.binary - before.binary, 0);
    assert_eq!(
        huge_get.calls(),
        0,
        "an over-cap object must be dropped before any GET"
    );
}

/// A second-page object whose GET returns 404 is counted as one unreadable gap;
/// the counter increments by exactly 1 and the first-page object is still scanned.
#[test]
fn non_success_get_on_second_page_object_counts_unreadable_once() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let page1 = truncated_page_with_token(&contents("present.txt", 16), "GONE-2");
    let page2 = final_page(&contents("missing.txt", 16));

    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    let _list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param("continuation-token", "GONE-2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page2);
    });
    let _o1 = mock_text_object(&server, "present.txt", "here\n");
    let _o2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_includes("missing.txt");
        then.status(404).body("NoSuchKey");
    });

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 1, "the first-page object must still be scanned");
    assert_eq!(errors.len(), 1, "the 404 object emits one error row");
    let err = errors[0].to_string();
    assert!(
        err.contains("GET returned 404") && err.contains("object was not scanned"),
        "error should name the 404 object, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "a failed page-2 object GET MUST bump SKIPPED_UNREADABLE by exactly 1"
    );
    assert_eq!(after.binary - before.binary, 0);
    assert_eq!(after.over_max_size - before.over_max_size, 0);
}

/// Independent skip categories on different pages accumulate independently: an
/// over-cap object on page 1 and a binary-extension object on page 2 bump their
/// OWN counters by exactly 1 each, and the one text object is scanned.
#[test]
fn mixed_skip_categories_across_pages_counted_independently() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let page1 = truncated_page_with_token(
        &format!(
            "{}{}",
            contents("ok.txt", 16),
            contents("big.txt", MAX_S3_OBJECT_BYTES + 1)
        ),
        "MIX-2",
    );
    let page2 = final_page(&contents("archive.rar", 512));

    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    let _list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param("continuation-token", "MIX-2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page2);
    });
    let _ok = mock_text_object(&server, "ok.txt", "ok\n");

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 1, "only the one text object is scanned");
    assert_eq!(
        errors.len(),
        2,
        "one over-cap error + one binary-extension error = two error rows"
    );

    let after = skip_counts();
    assert_eq!(
        after.over_max_size - before.over_max_size,
        1,
        "the page-1 over-cap object bumps SKIPPED_OVER_MAX_SIZE by exactly 1"
    );
    assert_eq!(
        after.binary - before.binary,
        1,
        "the page-2 binary-extension object bumps SKIPPED_BINARY by exactly 1"
    );
    assert_eq!(
        after.unreadable - before.unreadable,
        0,
        "no unreadable gap in this scan"
    );
    assert_eq!(after.source_truncated - before.source_truncated, 0);
}

// ---------------------------------------------------------------------------
// Listing-level (auth / transport) failures count ONE listing skip.
// ---------------------------------------------------------------------------

/// An auth failure on the first listing request (HTTP 403) is counted as exactly
/// one unreadable listing skip, surfaces one error row, and no object is fetched.
#[test]
fn listing_auth_failure_counts_one_listing_failure() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2");
        then.status(403)
            .body("<Error><Code>AccessDenied</Code></Error>");
    });
    // If the source wrongly tried to fetch an object, this would be hit.
    let any_object = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path_includes(".txt");
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 0, "a 403 listing yields no scanned chunk");
    assert_eq!(
        errors.len(),
        1,
        "a 403 listing surfaces exactly one error row"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("bucket request returned 403") && err.contains("objects were not scanned"),
        "error should name the failed S3 listing, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "a 403 listing failure MUST bump SKIPPED_UNREADABLE by exactly 1"
    );
    assert_eq!(
        after.over_max_size - before.over_max_size,
        0,
        "an auth failure is an unreadable listing gap, not an over-size skip"
    );
    assert_eq!(after.source_truncated - before.source_truncated, 0);
    assert_eq!(
        any_object.calls(),
        0,
        "no object GET may be issued after a failed listing"
    );
}

/// A mid-pagination listing failure (page 2 returns 500) is counted as exactly
/// one unreadable listing skip and surfaces one error row. NOTE: the current
/// `collect_s3_chunks` propagates the page-2 error with `?`, discarding the
/// already-collected page-1 chunk — so the result is a single error row. This
/// pins that behavior (the failure is loud + counted, not a silent false-clean).
#[test]
fn mid_pagination_listing_failure_counts_one_and_is_surfaced() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let page1 = truncated_page_with_token(&contents("first.txt", 16), "ERR-2");
    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    let _list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param("continuation-token", "ERR-2");
        then.status(500).body("InternalError");
    });
    let _o1 = mock_text_object(&server, "first.txt", "first\n");

    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(
        ok.len(),
        0,
        "the page-2 listing error is propagated with `?`, discarding page-1 chunks"
    );
    assert_eq!(errors.len(), 1, "exactly one listing-failure error row");
    let err = errors[0].to_string();
    assert!(
        err.contains("bucket request returned 500") && err.contains("objects were not scanned"),
        "error should name the failed page-2 S3 listing, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "a mid-pagination 500 listing failure MUST bump SKIPPED_UNREADABLE by exactly 1"
    );
    assert_eq!(after.source_truncated - before.source_truncated, 0);
}

/// Positive twin across pages: every object is scannable text, so the exact union
/// count is produced, the real object bytes flow into the chunk, and NO skip
/// counter moves.
#[test]
fn paginated_all_text_positive_twin_bytes_flow_and_no_skip() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let page1 = truncated_page_with_token(
        &format!("{}{}", contents("t1.txt", 40), contents("t2.txt", 16)),
        "POS-2",
    );
    let page2 = final_page(&format!(
        "{}{}",
        contents("t3.txt", 16),
        contents("t4.txt", 16)
    ));

    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    let _list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param("continuation-token", "POS-2");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page2);
    });
    // A real-shape AWS key on the first object so the scanned bytes are checkable.
    let _o1 = mock_text_object(&server, "t1.txt", "aws_key=AKIAQYLPMN5HFIQR7XYA\n"); // keyhog:ignore detector=aws-access-key (synthetic test fixture)
    let _o2 = mock_text_object(&server, "t2.txt", "two\n");
    let _o3 = mock_text_object(&server, "t3.txt", "three\n");
    let _o4 = mock_text_object(&server, "t4.txt", "four\n");

    let ok: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(
        ok.len(),
        4,
        "2 + 2 text objects must yield exactly 4 chunks"
    );
    let t1 = ok
        .iter()
        .find(|c| c.metadata.path.as_deref() == Some("regression-bucket/t1.txt"))
        .expect("t1.txt chunk must be present");
    assert!(
        t1.data.as_ref().contains("AKIAQYLPMN5HFIQR7XYA"), // keyhog:ignore detector=aws-access-key (synthetic test fixture)
        "the scanned chunk must carry the object body verbatim; got {:?}",
        t1.data.as_ref()
    );

    let after = skip_counts();
    assert_eq!(
        after.total(),
        before.total(),
        "a fully-scanned multi-page listing bumps no whole-file skip counter"
    );
    assert_eq!(
        after.source_truncated - before.source_truncated,
        0,
        "a listing that terminates on a non-truncated page is NOT a truncation"
    );
}
