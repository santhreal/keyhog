//! LANE sources-deep regression: the GCS JSON-API *request-building* contract —
//! the EXACT list URL, the EXACT per-object media URL (including percent-encoding
//! of object keys via `encode_object_key_path`), the ambient-bearer auth policy
//! (anonymous requests carry NO `Authorization` header; a bearer env on a
//! non-google endpoint is refused BEFORE any socket), endpoint trailing-slash
//! normalization, and malformed-bucket refusal — all driven through the public
//! `GcsSource::chunks()` production path against a loopback httpmock endpoint.
//!
//! This locks the request-shape internals that `gcs.rs` builds as raw strings:
//!   * `gcs_list_url`  -> `<endpoint>/storage/v1/b/<bucket>/o?alt=json&maxResults=1000`
//!   * `gcs_media_url` -> `<endpoint>/storage/v1/b/<bucket>/o/<enc-key>?alt=media`
//!   * `encode_object_key_path` -> per-segment percent-encoding that keeps `/`
//!     literal but encodes `#`, ` `, `?`, so an object key can never hijack the
//!     URL path/query (a raw `?`/`#` in a key would otherwise start the query /
//!     fragment and drop `alt=media`).
//!   * `gcs_bearer_token` -> env precedence (`GOOGLE_OAUTH_ACCESS_TOKEN` before
//!     `GCS_BEARER_TOKEN`), empty/control refusals, and the non-google
//!     credential-drop refusal (fail-closed, no anonymous fallback — Law 10).
//!   * `validate_bucket_name` -> boundary refusals (over-length, trailing dash).
//!
//! Distinct from `regression_gcs_listing_page.rs` (pagination / nextPageToken /
//! max_objects) and `regression_gcs_object_classify.rs` (object-key text/binary
//! classification, gs:// metadata, SSRF refusal): this file is about the exact
//! BYTES of the request line and the auth header, plus key percent-encoding.
//!
//! HOST-INDEPENDENCE: no accelerator is touched. Every network-reading test uses
//! a loopback httpmock endpoint, built via the `TestApi.gcs_source_with_endpoint*`
//! facade which sets the per-source `allow_private_endpoint` Tier-A config (not
//! env); `NET_LOCK` still serializes the exact ambient bearer-env state each test
//! needs so a parallel test can never observe the wrong credential state. The
//! bearer-refusal and malformed-bucket tests fail closed with NO socket opened.

#![cfg(feature = "gcs")]

mod support;

use httpmock::{Method, Mock, MockServer};
use keyhog_core::{Chunk, Source, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::sync::{Mutex, MutexGuard};
use support::split_chunk_results;

/// A syntactically valid GCS bucket name (3-222 chars, lowercase/digit/dash,
/// starts & ends alphanumeric) so `validate_bucket_name` passes and execution
/// reaches endpoint validation / the listing + media request builders.
const BUCKET: &str = "keyhog-gcs-req";

/// Serializes every test whose code path READS the process-global bearer-token
/// env (`GOOGLE_OAUTH_ACCESS_TOKEN`, `GCS_BEARER_TOKEN`). Each guard sets the
/// EXACT state it needs while holding the lock, so env observation is race-free
/// within this binary. (The private-endpoint allowance is per-source config now,
/// not env, so it needs no serialization.)
static NET_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    NET_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn clear_bearer_env() {
    std::env::remove_var("GOOGLE_OAUTH_ACCESS_TOKEN");
    std::env::remove_var("GCS_BEARER_TOKEN");
}

/// Loopback allowed + anonymous (no ambient bearer). Requests must carry no
/// `Authorization` header.
fn anon_guard() -> MutexGuard<'static, ()> {
    let guard = lock();
    clear_bearer_env();
    guard
}

/// Loopback allowed + a single `GCS_BEARER_TOKEN` set (no `GOOGLE_OAUTH…`).
fn gcs_bearer_guard(token: &str) -> MutexGuard<'static, ()> {
    let guard = lock();
    std::env::remove_var("GOOGLE_OAUTH_ACCESS_TOKEN");
    std::env::set_var("GCS_BEARER_TOKEN", token);
    guard
}

/// Loopback allowed + BOTH ambient token envs set (precedence probe).
fn both_tokens_guard(oauth: &str, gcs: &str) -> MutexGuard<'static, ()> {
    let guard = lock();
    std::env::set_var("GOOGLE_OAUTH_ACCESS_TOKEN", oauth);
    std::env::set_var("GCS_BEARER_TOKEN", gcs);
    guard
}

/// Hermetic guard for malformed-bucket tests: bucket validation aborts before any
/// env read or socket, so only the lock + a clean bearer state are needed.
fn hermetic_guard() -> MutexGuard<'static, ()> {
    let guard = lock();
    clear_bearer_env();
    guard
}

/// One GCS listing `items[]` entry with a base-10 string `size` (the JSON API
/// serializes object sizes as decimal strings).
fn item(name: &str, size: u64) -> String {
    format!(r#"{{"name":"{name}","size":"{size}"}}"#)
}

/// A terminal listing page (no `nextPageToken`), so the pagination loop stops.
fn final_page(items: &str) -> String {
    format!(r#"{{"items":[{items}]}}"#)
}

/// A listing mock for `<endpoint>/storage/v1/b/<bucket>/o?alt=json`.
fn mock_listing<'a>(server: &'a MockServer, bucket: &str, body: String) -> Mock<'a> {
    let path = format!("/storage/v1/b/{bucket}/o");
    server.mock(move |when, then| {
        when.method(Method::GET)
            .path(path)
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(body);
    })
}

/// A media-object GET mock for the EXACT (already percent-encoded) key path
/// `<endpoint>/storage/v1/b/<bucket>/o/<encoded_key>?alt=media`. httpmock matches
/// on `req.uri().path()`, which is percent-encoded verbatim (no decode), so a hit
/// count of 1 proves the client requested exactly this encoded path.
fn mock_media<'a>(
    server: &'a MockServer,
    bucket: &str,
    encoded_key_path: &str,
    body: &'static str,
) -> Mock<'a> {
    let path = format!("/storage/v1/b/{bucket}/o/{encoded_key_path}");
    server.mock(move |when, then| {
        when.method(Method::GET)
            .path(path)
            .query_param("alt", "media");
        then.status(200)
            .header("content-type", "text/plain")
            .body(body);
    })
}

/// Drive `GcsSource::chunks()` to completion and return the raw result rows.
fn collect_rows(source: impl Source) -> Vec<Result<Chunk, SourceError>> {
    source.chunks().collect()
}

// ==========================================================================
// Exact media-object URL (path + alt=media query)
// ==========================================================================

/// A nested text object is downloaded at EXACTLY
/// `/storage/v1/b/<bucket>/o/configs/prod/service.env?alt=media`, yields exactly
/// one chunk with the exact gs:// path, `source_type` "gcs", the LISTED size, and
/// the media GET fires exactly once.
#[test]
fn media_url_exact_path_and_alt_media_query() {
    let _g = anon_guard();
    let server = MockServer::start();
    let _list = mock_listing(
        &server,
        BUCKET,
        final_page(&item("configs/prod/service.env", 24)),
    );
    let obj = mock_media(
        &server,
        BUCKET,
        "configs/prod/service.env",
        "API_TOKEN=plain_value\n",
    );

    let rows = collect_rows(TestApi.gcs_source_with_endpoint(BUCKET, server.url("")));
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(errors.len(), 0, "a listed text object must not error");
    assert_eq!(chunks.len(), 1, "one listed object -> exactly one chunk");
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("gs://keyhog-gcs-req/configs/prod/service.env")
    );
    assert_eq!(chunks[0].metadata.source_type.as_ref(), "gcs");
    assert_eq!(chunks[0].metadata.size_bytes, Some(24));
    assert_eq!(
        obj.calls(),
        1,
        "the media GET must target /o/configs/prod/service.env?alt=media exactly once"
    );
}

/// A deeply nested key keeps every `/` LITERAL in the media path (segments are
/// encoded individually, separators preserved): the media GET hits
/// `/storage/v1/b/<bucket>/o/a/b/c/d/deep.txt?alt=media` exactly once.
#[test]
fn deep_nested_key_media_path_preserves_slashes() {
    let _g = anon_guard();
    let server = MockServer::start();
    let _list = mock_listing(&server, BUCKET, final_page(&item("a/b/c/d/deep.txt", 16)));
    let obj = mock_media(&server, BUCKET, "a/b/c/d/deep.txt", "deep\n");

    let rows = collect_rows(TestApi.gcs_source_with_endpoint(BUCKET, server.url("")));
    let (chunks, _errors) = split_chunk_results(&rows);

    assert_eq!(chunks.len(), 1);
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("gs://keyhog-gcs-req/a/b/c/d/deep.txt")
    );
    assert_eq!(
        obj.calls(),
        1,
        "nested key separators must stay literal in the media path"
    );
}

/// An object key containing `#` is percent-encoded to `%23` in the media URL, so
/// the `#` cannot start a URL fragment (which would drop `alt=media`). The media
/// GET hits `/o/weird%23hash.txt?alt=media`; the gs:// display path keeps the RAW
/// `#` (encoding is a wire concern only).
#[test]
fn object_key_with_hash_is_percent_encoded_in_media_url() {
    let _g = anon_guard();
    let server = MockServer::start();
    let _list = mock_listing(&server, BUCKET, final_page(&item("weird#hash.txt", 16)));
    let obj = mock_media(&server, BUCKET, "weird%23hash.txt", "hashy\n");

    let rows = collect_rows(TestApi.gcs_source_with_endpoint(BUCKET, server.url("")));
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(errors.len(), 0);
    assert_eq!(chunks.len(), 1, "the object with a '#' key must be scanned");
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("gs://keyhog-gcs-req/weird#hash.txt"),
        "gs:// display path carries the RAW key, not the %23-encoded form"
    );
    assert_eq!(
        obj.calls(),
        1,
        "'#' in the key MUST be sent as %23 (a fragment would drop alt=media)"
    );
}

/// A space in an object key segment is percent-encoded to `%20`; the media GET
/// hits `/o/dir/space%20file.txt?alt=media` exactly once.
#[test]
fn object_key_with_space_is_percent_encoded_in_media_url() {
    let _g = anon_guard();
    let server = MockServer::start();
    let _list = mock_listing(&server, BUCKET, final_page(&item("dir/space file.txt", 16)));
    let obj = mock_media(&server, BUCKET, "dir/space%20file.txt", "spaced\n");

    let rows = collect_rows(TestApi.gcs_source_with_endpoint(BUCKET, server.url("")));
    let (chunks, _errors) = split_chunk_results(&rows);

    assert_eq!(chunks.len(), 1);
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("gs://keyhog-gcs-req/dir/space file.txt")
    );
    assert_eq!(obj.calls(), 1, "a space in the key MUST be sent as %20");
}

/// A `?` in an object key is percent-encoded to `%3F`, so it cannot start the URL
/// query and hijack `alt=media`. The media GET matches BOTH the encoded path
/// `/o/q%3Fname.txt` AND the surviving `alt=media` query param.
#[test]
fn object_key_with_question_mark_is_percent_encoded_not_query() {
    let _g = anon_guard();
    let server = MockServer::start();
    let _list = mock_listing(&server, BUCKET, final_page(&item("q?name.txt", 16)));
    let obj = mock_media(&server, BUCKET, "q%3Fname.txt", "queried\n");

    let rows = collect_rows(TestApi.gcs_source_with_endpoint(BUCKET, server.url("")));
    let (chunks, _errors) = split_chunk_results(&rows);

    assert_eq!(chunks.len(), 1, "the '?'-key object must still be scanned");
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("gs://keyhog-gcs-req/q?name.txt")
    );
    assert_eq!(
        obj.calls(),
        1,
        "'?' in the key MUST be %3F so alt=media survives as the query"
    );
}

// ==========================================================================
// Exact list URL + first-page query string
// ==========================================================================

/// The FIRST listing request targets EXACTLY `/storage/v1/b/<bucket>/o` with
/// `alt=json`, `maxResults=1000`, and NO `pageToken` — the mock only matches all
/// four constraints simultaneously, so `calls()==1` proves the exact request line.
#[test]
fn exact_list_url_alt_json_maxresults_1000_no_pagetoken() {
    let _g = anon_guard();
    let server = MockServer::start();
    let list = server.mock(|when, then| {
        when.method(Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json")
            .query_param("maxResults", "1000")
            .query_param_missing("pageToken");
        then.status(200)
            .header("content-type", "application/json")
            .body(final_page(&item("app.log", 16)));
    });
    let _obj = mock_media(&server, BUCKET, "app.log", "log\n");

    let rows = collect_rows(TestApi.gcs_source_with_endpoint(BUCKET, server.url("")));
    let (chunks, _errors) = split_chunk_results(&rows);

    assert_eq!(chunks.len(), 1);
    assert_eq!(
        list.calls(),
        1,
        "list URL must be /storage/v1/b/<bucket>/o?alt=json&maxResults=1000 with no pageToken"
    );
}

// ==========================================================================
// Ambient-bearer auth policy
// ==========================================================================

/// An anonymous scan (no ambient bearer env) sends NEITHER the listing request
/// NOR the media request with an `Authorization` header. Both mocks require the
/// header to be ABSENT, so a hit count of 1 each proves no credential leaked.
#[test]
fn anonymous_requests_carry_no_authorization_header() {
    let _g = anon_guard();
    let server = MockServer::start();
    let list = server.mock(|when, then| {
        when.method(Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json")
            .header_missing("authorization");
        then.status(200)
            .header("content-type", "application/json")
            .body(final_page(&item("cfg.txt", 16)));
    });
    let obj = server.mock(|when, then| {
        when.method(Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/cfg.txt"))
            .query_param("alt", "media")
            .header_missing("authorization");
        then.status(200)
            .header("content-type", "text/plain")
            .body("cfg\n");
    });

    let rows = collect_rows(TestApi.gcs_source_with_endpoint(BUCKET, server.url("")));
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(errors.len(), 0);
    assert_eq!(chunks.len(), 1, "the anonymous object must be scanned");
    assert_eq!(
        list.calls(),
        1,
        "the listing request must carry NO Authorization header"
    );
    assert_eq!(
        obj.calls(),
        1,
        "the media request must carry NO Authorization header"
    );
}

/// A `GCS_BEARER_TOKEN` present with a non-google (loopback) endpoint and no
/// explicit token-forwarding flag is REFUSED before any request: the source
/// yields exactly one error naming the credential-drop refusal, and the listing
/// mock is never hit (fail-closed, no anonymous fallback — Law 10).
#[test]
fn gcs_bearer_on_non_google_endpoint_refused_before_any_request() {
    let _g = gcs_bearer_guard("ya29.non-google-secret");
    let server = MockServer::start();
    let list = mock_listing(&server, BUCKET, final_page(&item("never.txt", 16)));

    let rows = collect_rows(TestApi.gcs_source_with_endpoint(BUCKET, server.url("")));
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(chunks.len(), 0, "a refused credential must yield no chunk");
    assert_eq!(errors.len(), 1, "exactly one refusal error row");
    let message = errors[0].to_string();
    assert!(
        message.contains("GCS_BEARER_TOKEN is present but endpoint http://127.0.0.1"),
        "refusal must name the bearer env and the non-google endpoint, got: {message}"
    );
    assert!(
        message.contains(
            "is not googleapis.com; refusing to run anonymously after dropping credentials"
        ),
        "refusal must be the fail-closed credential-drop message, got: {message}"
    );
    assert_eq!(
        list.calls(),
        0,
        "no listing request may be issued after a refused credential"
    );
}

/// A `GCS_BEARER_TOKEN` set but empty is rejected with the EXACT operator message
/// (wrapped by `SourceError::Other`), before any request.
#[test]
fn empty_gcs_bearer_env_rejected_with_exact_message() {
    let _g = gcs_bearer_guard("");
    let server = MockServer::start();
    let list = mock_listing(&server, BUCKET, final_page(&item("never.txt", 16)));

    let rows = collect_rows(TestApi.gcs_source_with_endpoint(BUCKET, server.url("")));
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(chunks.len(), 0);
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors[0].to_string(),
        "failed to read source: GCS_BEARER_TOKEN is set but empty; unset it for \
         anonymous GCS access or provide a non-empty bearer token. Fix: adjust the \
         source settings or input so KeyHog can read plain text safely",
        "an empty bearer env must surface the exact wrapped refusal"
    );
    assert_eq!(
        list.calls(),
        0,
        "no request after an empty-bearer rejection"
    );
}

/// A `GCS_BEARER_TOKEN` containing a control character (embedded newline) is
/// rejected with the EXACT single-line-token message, before any request.
#[test]
fn control_char_gcs_bearer_env_rejected_with_exact_message() {
    let _g = gcs_bearer_guard("abc\ndef");
    let server = MockServer::start();
    let list = mock_listing(&server, BUCKET, final_page(&item("never.txt", 16)));

    let rows = collect_rows(TestApi.gcs_source_with_endpoint(BUCKET, server.url("")));
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(chunks.len(), 0);
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors[0].to_string(),
        "failed to read source: GCS_BEARER_TOKEN contains control characters; \
         provide a single-line bearer token. Fix: adjust the source settings or \
         input so KeyHog can read plain text safely",
        "a control-char bearer env must surface the exact wrapped refusal"
    );
    assert_eq!(list.calls(), 0, "no request after a control-char rejection");
}

/// `GOOGLE_OAUTH_ACCESS_TOKEN` takes precedence over `GCS_BEARER_TOKEN`: with both
/// set on a non-google endpoint, the credential-drop refusal names the OAuth env,
/// proving it is the one that was resolved (and would have been forwarded).
#[test]
fn google_oauth_token_takes_precedence_over_gcs_bearer() {
    let _g = both_tokens_guard("ya29.oauth-secret", "gcs-secret");
    let server = MockServer::start();
    let list = mock_listing(&server, BUCKET, final_page(&item("never.txt", 16)));

    let rows = collect_rows(TestApi.gcs_source_with_endpoint(BUCKET, server.url("")));
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(chunks.len(), 0);
    assert_eq!(errors.len(), 1);
    let message = errors[0].to_string();
    assert!(
        message.contains("GOOGLE_OAUTH_ACCESS_TOKEN is present but endpoint http://127.0.0.1"),
        "the OAuth env must be resolved first (precedence), got: {message}"
    );
    assert!(
        !message.contains("GCS_BEARER_TOKEN is present"),
        "the lower-precedence GCS_BEARER_TOKEN must not be the one named, got: {message}"
    );
    assert_eq!(list.calls(), 0);
}

// ==========================================================================
// Endpoint trailing-slash normalization (no double slash in built URLs)
// ==========================================================================

/// An endpoint with a trailing `/` is normalized so the built media URL has a
/// SINGLE slash before `storage` (no `//storage`). The object is fetched at the
/// exact `/storage/v1/b/<bucket>/o/norm.txt?alt=media` path.
#[test]
fn endpoint_trailing_slash_normalized_no_double_slash() {
    let _g = anon_guard();
    let server = MockServer::start();
    let _list = mock_listing(&server, BUCKET, final_page(&item("norm.txt", 16)));
    let obj = mock_media(&server, BUCKET, "norm.txt", "normalized\n");

    let endpoint_with_slash = format!("{}/", server.url(""));
    let rows = collect_rows(TestApi.gcs_source_with_endpoint(BUCKET, endpoint_with_slash));
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(
        errors.len(),
        0,
        "a trailing-slash endpoint must still resolve"
    );
    assert_eq!(chunks.len(), 1);
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("gs://keyhog-gcs-req/norm.txt")
    );
    assert_eq!(
        obj.calls(),
        1,
        "trailing slash must be trimmed so the path has a single leading /storage"
    );
}

// ==========================================================================
// Malformed bucket -> refusal before any request (boundary cases)
// ==========================================================================

/// A bucket ending in a non-alphanumeric character (trailing dash) is refused by
/// `validate_bucket_name` with the exact bucket-bearing message, before any URL is
/// built or socket opened.
#[test]
fn bucket_ending_in_dash_is_refused() {
    let _g = hermetic_guard();
    let rows = collect_rows(
        TestApi.gcs_source_with_endpoint("my-bucket-", "https://storage.googleapis.com"),
    );
    assert_eq!(
        rows.len(),
        1,
        "a malformed bucket aborts with one error row"
    );
    let message = match &rows[0] {
        Ok(chunk) => panic!("bucket must be refused, got chunk: {:?}", chunk.metadata),
        Err(error) => error.to_string(),
    };
    assert!(
        message.contains("invalid GCS bucket 'my-bucket-'"),
        "a trailing-dash bucket must be refused by name, got: {message}"
    );
}

/// A bucket over the 222-character length ceiling is refused for length (the FIRST
/// check in `validate_bucket_name`), before any URL is built.
#[test]
fn over_length_bucket_is_refused_for_length() {
    let _g = hermetic_guard();
    let long_bucket = "a".repeat(223);
    let rows = collect_rows(
        TestApi.gcs_source_with_endpoint(long_bucket, "https://storage.googleapis.com"),
    );
    assert_eq!(rows.len(), 1);
    let message = match &rows[0] {
        Ok(chunk) => panic!("bucket must be refused, got chunk: {:?}", chunk.metadata),
        Err(error) => error.to_string(),
    };
    assert!(
        message.contains("invalid GCS bucket name length"),
        "a 223-char bucket must be refused for length, got: {message}"
    );
}

// ==========================================================================
// Boundary positive: minimum-length (3-char) bucket builds a valid request
// ==========================================================================

/// A 3-character bucket (the minimum valid length) passes validation and builds
/// the exact list + media URLs against that bucket, yielding one scanned chunk.
#[test]
fn min_length_three_char_bucket_builds_request() {
    let _g = anon_guard();
    let bucket = "abc";
    let server = MockServer::start();
    let _list = mock_listing(&server, bucket, final_page(&item("k.txt", 16)));
    let obj = mock_media(&server, bucket, "k.txt", "min\n");

    let rows = collect_rows(TestApi.gcs_source_with_endpoint(bucket, server.url("")));
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(errors.len(), 0, "a 3-char bucket is valid");
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].metadata.path.as_deref(), Some("gs://abc/k.txt"));
    assert_eq!(
        obj.calls(),
        1,
        "the media GET targets /b/abc/o/k.txt?alt=media"
    );
}
