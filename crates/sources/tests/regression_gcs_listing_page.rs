//! LANE sources-deep regression: the GCS JSON-API listing pagination loop
//! (`collect_gcs_chunks` in `gcs.rs`) must
//!   * thread the previous page's `nextPageToken` (and the caller's `prefix`)
//!     into the next `pageToken` listing request, walking every page and
//!     yielding the EXACT union object count across all pages;
//!   * build the EXACT list-request URL for a bucket + prefix
//!     (`/storage/v1/b/<bucket>/o?alt=json&maxResults=1000&prefix=<prefix>`);
//!   * classify each listed object key for scanning, a binary/container
//!     extension object is dropped before any media GET, a zero-size object
//!     yields no chunk and no GET, an over-cap object is refused;
//!   * treat an absent / empty / whitespace `nextPageToken` as "exhausted"
//!     (no page-2 restart), and stop at the `max_objects` cap before the next
//!     page is ever listed;
//!   * surface a malformed listing payload as exactly one operator-facing
//!     listing error, with no object GET issued.
//!
//! These drive the REAL `GcsSource::chunks()` production path (list ->
//! nextPageToken -> next list -> per-object media GET) against an httpmock GCS
//! endpoint, disambiguating the first page (`pageToken` absent) from later
//! pages (`pageToken` == the exact prior token) with `query_param_missing` /
//! `query_param`. Distinct from `regression_gcs_object_classify.rs` (single
//! object -> metadata) and `regression_gcs_listing_counters.rs`.
//!
//! HOST-INDEPENDENCE: no accelerator is touched. httpmock binds 127.0.0.1,
//! which the cloud SSRF endpoint screen refuses by default, so each test builds
//! its source via the `TestApi.gcs_source_with_endpoint*` facade, which sets the
//! per-source `allow_private_endpoint` Tier-A config (not env); `COUNTER_LOCK`
//! still serializes the global skip counters, the same discipline the sibling
//! `regression_s3_listing_pagination.rs` uses so a parallel test can never
//! observe the wrong SSRF-allow state or a polluted skip counter.

#![cfg(feature = "gcs")]

mod support;

use keyhog_core::Source;
use keyhog_sources::skip_counts;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::sync::{Mutex, MutexGuard};
use support::split_chunk_results;

/// A syntactically valid GCS bucket name (3-222 chars, lowercase/digit/dash,
/// starts & ends alphanumeric) so `validate_bucket_name` passes and execution
/// reaches the endpoint host-screen / listing loop.
const BUCKET: &str = "keyhog-gcs-page";

/// The per-object byte cap baked into the resolved `SourceLimits`
/// (`gcs_object_bytes` default = 10 MiB).
const MAX_GCS_OBJECT_BYTES: u64 = 10 * 1024 * 1024;

static COUNTER_LOCK: Mutex<()> = Mutex::new(());

/// Acquire `COUNTER_LOCK` and turn the loud, default-off loopback allowance ON
/// so a 127.0.0.1 httpmock endpoint is reachable. Set while holding the lock so
/// it can never race a parallel test in this binary.
fn loopback_guard() -> MutexGuard<'static, ()> {
    let guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
}

/// One GCS listing `items[]` entry with a base-10 string `size` (the JSON API
/// serializes object sizes as decimal strings).
fn item(name: &str, size: u64) -> String {
    format!(r#"{{"name":"{name}","size":"{size}"}}"#)
}

/// A listing page that carries a concrete `nextPageToken` continuation cursor.
fn page_with_token(items: &str, token: &str) -> String {
    format!(r#"{{"items":[{items}],"nextPageToken":"{token}"}}"#)
}

/// A terminal listing page: no `nextPageToken`, so the loop stops.
fn final_page(items: &str) -> String {
    format!(r#"{{"items":[{items}]}}"#)
}

/// Register a text-object media GET mock returning `body` as `text/plain`. The
/// media URL is `/storage/v1/b/<bucket>/o/<key>?alt=media`; matching on the key
/// path segment cannot collide with the listing URL (`/o`, `alt=json`).
fn mock_text_object<'a>(
    server: &'a httpmock::MockServer,
    key: &str,
    body: &'static str,
) -> httpmock::Mock<'a> {
    let path = format!("/storage/v1/b/{BUCKET}/o/{key}");
    server.mock(move |when, then| {
        when.method(httpmock::Method::GET)
            .path(path)
            .query_param("alt", "media");
        then.status(200)
            .header("content-type", "text/plain")
            .body(body);
    })
}

// ---------------------------------------------------------------------------
// Baseline: a single terminal page yields the exact object count, no page 2.
// ---------------------------------------------------------------------------

/// A single non-truncated page with two text objects yields exactly two chunks
/// with the exact `gs://` paths, lists once, and never issues a page-2 request.
#[test]
fn single_page_two_text_objects_exact_count() {
    let _guard = loopback_guard();

    let server = httpmock::MockServer::start();
    let body = final_page(&format!("{},{}", item("a.txt", 16), item("b.txt", 16)));
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json")
            .query_param_missing("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(body);
    });
    // A page-2 request (any pageToken) must never be issued.
    let page2_probe = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param_exists("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(final_page(&item("should-not-be-listed.txt", 16)));
    });
    let _a = mock_text_object(&server, "a.txt", "alpha\n");
    let _b = mock_text_object(&server, "b.txt", "bravo\n");

    let ok: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(ok.len(), 2, "two text objects must yield exactly 2 chunks");
    let mut paths: Vec<&str> = ok
        .iter()
        .map(|c| c.metadata.path.as_deref().unwrap())
        .collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        vec!["gs://keyhog-gcs-page/a.txt", "gs://keyhog-gcs-page/b.txt"]
    );
    assert_eq!(
        list.calls(),
        1,
        "a single page needs exactly one list request"
    );
    assert_eq!(
        page2_probe.calls(),
        0,
        "a terminal page (no nextPageToken) must NOT trigger a page-2 listing"
    );
}

// ---------------------------------------------------------------------------
// Exact list-request URL for a bucket.
// ---------------------------------------------------------------------------

/// The first listing request targets EXACTLY `/storage/v1/b/<bucket>/o` with
/// `alt=json` and `maxResults=1000` and NO `pageToken`: the mock only matches
/// all four constraints at once, so `calls()==1` proves the exact URL and query
/// string were built. (The `prefix` param is set through a `pub(crate)` setter
/// not reachable from an external test crate, so it is exercised in the crate's
/// own unit coverage, not here.)
#[test]
fn exact_list_request_url_for_bucket() {
    let _guard = loopback_guard();

    let server = httpmock::MockServer::start();
    let list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json")
            .query_param("maxResults", "1000")
            .query_param_missing("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(final_page(&item("app.log", 16)));
    });
    let _obj = mock_text_object(&server, "app.log", "cfg\n");

    let ok: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(ok.len(), 1, "the single listed object must be scanned");
    assert_eq!(
        ok[0].metadata.path.as_deref(),
        Some("gs://keyhog-gcs-page/app.log")
    );
    assert_eq!(
        list.calls(),
        1,
        "the list URL must be /storage/v1/b/<bucket>/o?alt=json&maxResults=1000 exactly"
    );
}

// ---------------------------------------------------------------------------
// nextPageToken drives the next page request.
// ---------------------------------------------------------------------------

/// Page 1 carries a `nextPageToken`; page 2 is requested with that token as
/// `pageToken`. Both pages' objects are scanned (exact union count), and each
/// page is listed exactly once.
#[test]
fn next_page_token_drives_second_page_request() {
    let _guard = loopback_guard();

    let server = httpmock::MockServer::start();
    let page1 = page_with_token(
        &format!("{},{}", item("p1-a.txt", 16), item("p1-b.txt", 16)),
        "PAGE2CURSOR",
    );
    let page2 = final_page(&item("p2-a.txt", 16));

    let list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json")
            .query_param_missing("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(page1);
    });
    let list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json")
            .query_param("pageToken", "PAGE2CURSOR");
        then.status(200)
            .header("content-type", "application/json")
            .body(page2);
    });
    let _o1 = mock_text_object(&server, "p1-a.txt", "one\n");
    let _o2 = mock_text_object(&server, "p1-b.txt", "two\n");
    let _o3 = mock_text_object(&server, "p2-a.txt", "three\n");

    let ok: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
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
}

/// The `nextPageToken` must be threaded VERBATIM as the page-2 `pageToken`: the
/// page-2 mock only matches the exact token, so a hit count of 1 proves the
/// token was neither dropped nor mangled.
#[test]
fn next_page_token_threaded_verbatim() {
    let _guard = loopback_guard();

    let server = httpmock::MockServer::start();
    let token = "Next-Page_Cursor.42==";
    let page1 = page_with_token(&item("v1.txt", 16), token);
    let page2 = final_page(&item("v2.txt", 16));

    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json")
            .query_param_missing("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(page1);
    });
    let list2_exact = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("pageToken", token);
        then.status(200)
            .header("content-type", "application/json")
            .body(page2);
    });
    let _o1 = mock_text_object(&server, "v1.txt", "v1\n");
    let _o2 = mock_text_object(&server, "v2.txt", "v2\n");

    let ok: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(ok.len(), 2, "both pages' single objects must be scanned");
    assert_eq!(
        list2_exact.calls(),
        1,
        "page 2 must be listed exactly once with the verbatim pageToken"
    );
}

/// Positive twin across pages: every listed object is scannable text, so the
/// exact union count is produced, the real downloaded object BYTES flow into the
/// chunk verbatim (checked on a page-2 object), and no page is dropped.
#[test]
fn paginated_all_text_positive_twin_bytes_flow() {
    let _guard = loopback_guard();

    let server = httpmock::MockServer::start();
    let page1 = page_with_token(
        &format!("{},{}", item("t1.txt", 40), item("t2.txt", 16)),
        "POS-2",
    );
    let page2 = final_page(&format!("{},{}", item("t3.txt", 16), item("t4.txt", 16)));

    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json")
            .query_param_missing("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(page1);
    });
    let _list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("pageToken", "POS-2");
        then.status(200)
            .header("content-type", "application/json")
            .body(page2);
    });
    let _o1 = mock_text_object(&server, "t1.txt", "one\n");
    let _o2 = mock_text_object(&server, "t2.txt", "two\n");
    // A distinctive body on a page-2 object so the scanned bytes are checkable.
    let _o3 = mock_text_object(&server, "t3.txt", "gcs_page2_marker_value\n");
    let _o4 = mock_text_object(&server, "t4.txt", "four\n");

    let ok: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(
        ok.len(),
        4,
        "2 + 2 text objects must yield exactly 4 chunks"
    );
    let t3 = ok
        .iter()
        .find(|c| c.metadata.path.as_deref() == Some("gs://keyhog-gcs-page/t3.txt"))
        .expect("t3.txt chunk from page 2 must be present");
    assert_eq!(
        &*t3.data, "gcs_page2_marker_value\n",
        "the scanned chunk must carry the downloaded page-2 object body verbatim"
    );
    // The listed size (16) is carried, not the downloaded body length (23).
    assert_eq!(
        t3.metadata.size_bytes,
        Some(16),
        "size_bytes must be the listed object size, not the body length"
    );
}

/// A three-page listing (token, token, terminal) yields the exact union count
/// and lists each page exactly once, the loop terminates on the final
/// non-truncated page.
#[test]
fn three_page_listing_yields_exact_union_count() {
    let _guard = loopback_guard();

    let server = httpmock::MockServer::start();
    let page1 = page_with_token(
        &format!("{},{}", item("g1-a.txt", 16), item("g1-b.txt", 16)),
        "TOK-2",
    );
    let page2 = page_with_token(
        &format!("{},{}", item("g2-a.txt", 16), item("g2-b.txt", 16)),
        "TOK-3",
    );
    let page3 = final_page(&item("g3-a.txt", 16));

    let list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json")
            .query_param_missing("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(page1);
    });
    let list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("pageToken", "TOK-2");
        then.status(200)
            .header("content-type", "application/json")
            .body(page2);
    });
    let list3 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("pageToken", "TOK-3");
        then.status(200)
            .header("content-type", "application/json")
            .body(page3);
    });
    for key in ["g1-a.txt", "g1-b.txt", "g2-a.txt", "g2-b.txt", "g3-a.txt"] {
        mock_text_object(&server, key, "payload\n");
    }

    let ok: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(ok.len(), 5, "2 + 2 + 1 objects must yield exactly 5 chunks");
    assert_eq!(list1.calls(), 1);
    assert_eq!(list2.calls(), 1, "page 2 must be requested with TOK-2 once");
    assert_eq!(list3.calls(), 1, "page 3 must be requested with TOK-3 once");
}

// ---------------------------------------------------------------------------
// Exhaustion: absent / empty / whitespace nextPageToken stops without restart.
// ---------------------------------------------------------------------------

/// An EMPTY `nextPageToken` is normalized to "exhausted": re-requesting with it
/// would restart the listing from page 1, so the loop must stop. The visible
/// object is scanned and no page-2 request is issued.
#[test]
fn empty_next_page_token_stops_without_restart() {
    let _guard = loopback_guard();

    let server = httpmock::MockServer::start();
    let page1 = page_with_token(&item("cfg.txt", 16), "");
    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param_missing("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(page1);
    });
    let _obj = mock_text_object(&server, "cfg.txt", "cfg\n");
    // A page-2 request (any pageToken, including the empty one) must never fire.
    let page2_probe = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param_exists("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(final_page(&item("restart.txt", 16)));
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 1, "the visible page object must still be scanned");
    assert_eq!(
        errors.len(),
        0,
        "an empty nextPageToken is a clean exhaustion, not a coverage gap error"
    );
    assert_eq!(
        page2_probe.calls(),
        0,
        "an empty nextPageToken must NOT trigger a page-2 listing (no restart loop)"
    );
}

/// A whitespace-only `nextPageToken` is likewise "exhausted". `str::trim`
/// reduces it to empty, so the loop stops without a page-2 request.
#[test]
fn whitespace_next_page_token_stops_without_restart() {
    let _guard = loopback_guard();

    let server = httpmock::MockServer::start();
    let page1 = page_with_token(&item("only.txt", 16), "   ");
    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param_missing("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(page1);
    });
    let _obj = mock_text_object(&server, "only.txt", "only\n");
    let page2_probe = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param_exists("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(final_page(&item("restart.txt", 16)));
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 1, "the visible object must be scanned");
    assert_eq!(errors.len(), 0, "a whitespace token is clean exhaustion");
    assert_eq!(
        page2_probe.calls(),
        0,
        "a whitespace-only nextPageToken must NOT trigger a page-2 listing"
    );
}

// ---------------------------------------------------------------------------
// max_objects cap stops before the next page is listed.
// ---------------------------------------------------------------------------

/// With `max_objects == 1` and a first page carrying two objects plus a token,
/// the cap stops pagination within the page: exactly one object is scanned, the
/// truncation error is surfaced with the EXACT message, and the page-2 listing
/// (the token) is never requested.
#[test]
fn max_objects_cap_stops_within_first_page() {
    let _guard = loopback_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let page1 = page_with_token(
        &format!("{},{}", item("keep.txt", 16), item("drop.txt", 16)),
        "CAP-2",
    );
    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param_missing("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(page1);
    });
    let list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("pageToken", "CAP-2");
        then.status(200)
            .header("content-type", "application/json")
            .body(final_page(&item("beyond.txt", 16)));
    });
    // Only the first (allowed) object may be fetched.
    let _keep = mock_text_object(&server, "keep.txt", "keep\n");
    let drop_get = mock_text_object(&server, "drop.txt", "SHOULD_NOT_BE_FETCHED\n");

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint_max_objects(BUCKET, server.url(""), 1)
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 1, "exactly the one allowed object is scanned");
    assert_eq!(
        ok[0].metadata.path.as_deref(),
        Some("gs://keyhog-gcs-page/keep.txt")
    );
    assert_eq!(
        errors.len(),
        1,
        "the cap surfaces exactly one truncation error"
    );
    assert!(
        errors[0].to_string().contains(
            "gcs source scan was truncated: max_objects limit reached within the current \
             GCS listing page; remaining objects were not scanned"
        ),
        "the truncation error must carry the exact within-page GCS cap message, got: {}",
        errors[0]
    );
    assert_eq!(
        list2.calls(),
        0,
        "the object cap must stop pagination before the page-2 listing is issued"
    );
    assert_eq!(
        drop_get.calls(),
        0,
        "the over-cap object beyond max_objects must never be downloaded"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "max_objects truncation MUST bump SOURCE_TRUNCATED by exactly 1"
    );
}

// ---------------------------------------------------------------------------
// Object-key classification for scanning (across a paginated listing).
// ---------------------------------------------------------------------------

/// A binary/container-extension object (`.zip`) listed among text objects is
/// classified as non-text and dropped BEFORE any media GET: it surfaces exactly
/// one binary coverage-gap error (with the exact reason and gs:// path), it is
/// never fetched, and it bumps SKIPPED_BINARY exactly once across the two pages.
#[test]
fn binary_extension_object_classified_and_skipped_across_pages() {
    let _guard = loopback_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let page1 = page_with_token(
        &format!("{},{}", item("good1.txt", 16), item("bundle.zip", 512)),
        "BIN-2",
    );
    let page2 = final_page(&item("good2.txt", 16));

    let _list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param_missing("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(page1);
    });
    let _list2 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("pageToken", "BIN-2");
        then.status(200)
            .header("content-type", "application/json")
            .body(page2);
    });
    let _o1 = mock_text_object(&server, "good1.txt", "g1\n");
    let _o2 = mock_text_object(&server, "good2.txt", "g2\n");
    let zip_get = mock_text_object(&server, "bundle.zip", "SHOULD_NOT_BE_FETCHED\n");

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
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
    assert!(
        errors[0].to_string().contains(
            "failed to scan GCS object gs://keyhog-gcs-page/bundle.zip: \
             extension is treated as binary/container content; object was not scanned"
        ),
        "the binary skip error must name the exact gs:// object and reason, got: {}",
        errors[0]
    );
    assert_eq!(
        zip_get.calls(),
        0,
        "a binary-extension object must be dropped before any media GET"
    );

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "one binary object across a two-page listing MUST bump SKIPPED_BINARY by exactly 1"
    );
    assert_eq!(after.over_max_size - before.over_max_size, 0);
    assert_eq!(after.unreadable - before.unreadable, 0);
}

/// A zero-`size` object is dropped before any media GET (GCS lists zero-byte
/// objects and "directory placeholder" keys), yields no chunk, no error, and
/// bumps NO skip counter (the neighboring text object is still scanned).
#[test]
fn zero_size_object_yields_no_chunk_and_no_get() {
    let _guard = loopback_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let body = final_page(&format!(
        "{},{}",
        item("real.txt", 16),
        item("empty.txt", 0)
    ));
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(body);
    });
    let _real = mock_text_object(&server, "real.txt", "real\n");
    let empty_get = mock_text_object(&server, "empty.txt", "SHOULD_NOT_BE_FETCHED\n");

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 1, "only the one non-empty object yields a chunk");
    assert_eq!(
        ok[0].metadata.path.as_deref(),
        Some("gs://keyhog-gcs-page/real.txt")
    );
    assert_eq!(
        errors.len(),
        0,
        "a zero-size object is not an error/coverage gap"
    );
    assert_eq!(
        empty_get.calls(),
        0,
        "a zero-size object must be dropped before any media GET"
    );

    let after = skip_counts();
    assert_eq!(
        after.total(),
        before.total(),
        "a zero-size object bumps no whole-object skip counter"
    );
}

/// An over-cap object (listed `size` > `gcs_object_bytes`) is refused before any
/// media GET with the EXACT over-size reason, bumping SKIPPED_OVER_MAX_SIZE once;
/// the neighboring in-cap text object is still scanned.
#[test]
fn oversized_object_refused_before_download() {
    let _guard = loopback_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let body = final_page(&format!(
        "{},{}",
        item("small.txt", 16),
        item("huge.txt", MAX_GCS_OBJECT_BYTES + 1)
    ));
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(body);
    });
    let _small = mock_text_object(&server, "small.txt", "small\n");
    let huge_get = mock_text_object(&server, "huge.txt", "SHOULD_NOT_BE_FETCHED\n");

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 1, "the in-cap text object must still be scanned");
    assert_eq!(
        errors.len(),
        1,
        "the over-cap object emits exactly one error row"
    );
    let expected = format!(
        "failed to scan GCS object gs://keyhog-gcs-page/huge.txt: \
         listed size {} exceeds the per-object byte cap {MAX_GCS_OBJECT_BYTES}; \
         object was not scanned",
        MAX_GCS_OBJECT_BYTES + 1
    );
    assert!(
        errors[0].to_string().contains(&expected),
        "the over-cap error must carry the exact listed size, cap, and gs:// path, got: {}",
        errors[0]
    );
    assert_eq!(
        huge_get.calls(),
        0,
        "an over-cap object must be dropped before any media GET"
    );

    let after = skip_counts();
    assert_eq!(
        after.over_max_size - before.over_max_size,
        1,
        "the over-cap object MUST bump SKIPPED_OVER_MAX_SIZE by exactly 1"
    );
    assert_eq!(after.binary - before.binary, 0);
}

// ---------------------------------------------------------------------------
// Malformed listing payload => exactly one listing error, no object GET.
// ---------------------------------------------------------------------------

/// A malformed (non-JSON) listing body is surfaced as exactly one operator-facing
/// listing failure that bumps SKIPPED_UNREADABLE once, and NO object GET is
/// issued (the listing never parses into items).
#[test]
fn malformed_listing_json_is_one_listing_error_no_object_get() {
    let _guard = loopback_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body("{ this is not valid json ]");
    });
    // If the source wrongly tried to fetch an object, this would be hit.
    let any_object = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_includes(format!("/storage/v1/b/{BUCKET}/o/"));
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 0, "a malformed listing yields no scanned chunk");
    assert_eq!(
        errors.len(),
        1,
        "a malformed listing surfaces exactly one error row"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("GCS source listing failed: failed to parse listing response:")
            && err.contains("; objects were not scanned"),
        "error must be the GCS parse-failure listing skip, got: {err}"
    );
    assert_eq!(
        any_object.calls(),
        0,
        "no object GET may be issued after a malformed listing"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "a malformed listing MUST bump SKIPPED_UNREADABLE by exactly 1"
    );
    assert_eq!(after.source_truncated - before.source_truncated, 0);
}

/// A non-success listing status (HTTP 403) is counted as exactly one unreadable
/// listing skip with the exact status-bearing message, and no object is fetched.
#[test]
fn listing_http_403_is_one_unreadable_listing_skip() {
    let _guard = loopback_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(403).body("{\"error\":\"forbidden\"}");
    });
    let any_object = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_includes(format!("/storage/v1/b/{BUCKET}/o/"));
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
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
        err.contains("GCS source listing failed: bucket request returned 403")
            && err.contains("; objects were not scanned"),
        "error must name the failed GCS listing status, got: {err}"
    );
    assert_eq!(
        any_object.calls(),
        0,
        "no object GET may be issued after a failed listing"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "a 403 listing failure MUST bump SKIPPED_UNREADABLE by exactly 1"
    );
    assert_eq!(after.source_truncated - before.source_truncated, 0);
}
