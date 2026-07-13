//! Regression: GCS object-key / listing classification, gs:// display-path
//! mapping, endpoint SSRF refusal, and malformed-input errors.
//!
//! These lock the CONCRETE contracts of the `gcs` source backend:
//!   * `is_probably_text_object_key`: which listed object keys are downloaded
//!     as text vs. prefiltered as binary/container content (host-independent
//!     pure logic).
//!   * `is_binary_content_type`: the Content-Type binary screen.
//!   * `endpoint_is_google`: the googleapis.com host match that gates ambient
//!     bearer-token forwarding (fail-closed on a malformed endpoint).
//!   * A listed object maps to EXACTLY `gs://<bucket>/<key>` with `source_type`
//!     "gcs" and the listed `size_bytes` (driven end-to-end through the public
//!     `GcsSource::chunks()` production path against a loopback mock server).
//!   * A private / loopback / link-local endpoint is REFUSED before any socket
//!     is opened, via the fleet-canonical `keyhog_verifier::ssrf` classifier
//!     shared with S3/Azure/Web (never a silent degrade).
//!   * Malformed bucket names and malformed listing payloads yield the exact
//!     operator-facing error string.
//!
//! HOST-INDEPENDENCE: no accelerator is touched. The SSRF-refusal and
//! malformed-input assertions are fully hermetic, they abort inside
//! `validate_bucket_name` / `validate_cloud_endpoint` BEFORE any network I/O, so they
//! are deterministic on every host. The two mock-server tests use a loopback
//! httpmock endpoint and therefore build their source with
//! `allow_private_endpoint = true` (per-source Tier-A config, NOT a process-
//! global env); the SSRF-refusal tests build with the default `false`. Each
//! source carries its own screen state, so there is no env and no lock to hold.

#![cfg(feature = "gcs")]

mod support;

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use support::split_chunk_results;

/// A syntactically valid GCS bucket name (3-222 chars, lowercase/digit/dash,
/// starts & ends alphanumeric) so `validate_bucket_name` passes and execution
/// reaches the endpoint host-screen / listing.
const BUCKET: &str = "keyhog-gcs-classify";

/// The exact SSRF-refusal string emitted for a private/loopback/link-local/
/// metadata endpoint host (`source` == "GCS"). Load-bearing: the refusal is
/// host-based, not a generic "invalid endpoint".
const GCS_SSRF_REFUSAL: &str =
    "refusing GCS endpoint: host is a private, loopback, link-local, or cloud-metadata address (SSRF)";

// The private-endpoint allowance is now per-source Tier-A config
// (`HttpClientConfig.allow_private_endpoint`), threaded into each source by the
// `TestApi.gcs_source_with_endpoint*` builders, the SSRF-refusal tests drive
// `allow_private = false` and the loopback mock tests drive `true`, with no
// process-global `KEYHOG_ALLOW_PRIVATE_CLOUD_ENDPOINT` env and so no lock.

/// Drive `GcsSource::chunks()` for a custom `endpoint` and return the single
/// error message string. An endpoint refused before listing yields exactly one
/// error row, so this asserts that shape too.
fn single_endpoint_error(endpoint: &str) -> String {
    // SSRF-refusal path: the screen must be ACTIVE (allow_private = false).
    let source = TestApi.gcs_source_with_endpoint_allow_private(BUCKET, endpoint, false);
    let rows: Vec<_> = source.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "a refused endpoint must abort with exactly one error row before listing; \
         got {} row(s) for endpoint {endpoint}",
        rows.len()
    );
    match &rows[0] {
        Ok(chunk) => panic!(
            "endpoint {endpoint} must be REFUSED, but the source yielded a scanned chunk with metadata {:?}",
            chunk.metadata
        ),
        Err(error) => error.to_string(),
    }
}

/// Drive `chunks()` for an invalid `bucket` against a valid public endpoint and
/// return the single error message. `validate_bucket_name` runs BEFORE endpoint
/// validation, so this aborts with no network and no env read.
fn single_bucket_error(bucket: &str) -> String {
    let source = TestApi.gcs_source_with_endpoint(bucket, "https://storage.googleapis.com");
    let rows: Vec<_> = source.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "an invalid bucket must abort with exactly one error row; got {} for bucket {bucket:?}",
        rows.len()
    );
    match &rows[0] {
        Ok(chunk) => panic!(
            "bucket {bucket:?} must be REFUSED, but the source yielded a chunk: {:?}",
            chunk.metadata
        ),
        Err(error) => error.to_string(),
    }
}

// ==========================================================================
// Object-key text/binary classification (pure, host-independent)
// ==========================================================================

#[test]
fn text_and_extensionless_object_keys_classify_as_text() {
    // A plain text extension, a nested key, and an extensionless key are all
    // downloaded and scanned as text.
    assert!(TestApi.cloud_is_probably_text_object_key("config.txt"));
    assert!(TestApi.cloud_is_probably_text_object_key("logs/2026/app.log"));
    assert!(TestApi.cloud_is_probably_text_object_key("service.env"));
    // No extension -> whole key is the filename segment, recall-safe as text.
    assert!(TestApi.cloud_is_probably_text_object_key("extensionless-secret"));
    assert!(TestApi.cloud_is_probably_text_object_key("deploy/credentials"));
    // A trailing-dot / empty-extension key has no usable extension -> text.
    assert!(TestApi.cloud_is_probably_text_object_key("dotfiles/.gitignore"));
}

#[test]
fn binary_and_container_object_keys_classify_as_non_text() {
    // Archive/container extensions from the cloud binary prefilter.
    assert!(!TestApi.cloud_is_probably_text_object_key("bundle.zip"));
    assert!(!TestApi.cloud_is_probably_text_object_key("dump.tar.gz"));
    assert!(!TestApi.cloud_is_probably_text_object_key("backup.7z"));
    // Extension match is case-insensitive.
    assert!(!TestApi.cloud_is_probably_text_object_key("BUNDLE.ZIP"));
    // Default-skip binary extensions (image / executable / db) also refused.
    assert!(!TestApi.cloud_is_probably_text_object_key("photo.png"));
    assert!(!TestApi.cloud_is_probably_text_object_key("app/native.exe"));
    assert!(!TestApi.cloud_is_probably_text_object_key("module.wasm"));
    assert!(!TestApi.cloud_is_probably_text_object_key("cache.sqlite"));
}

#[test]
fn binary_content_type_classification_is_exact() {
    // image/audio/video media types and zip/gzip are binary.
    assert!(TestApi.cloud_is_binary_content_type("image/jpeg"));
    assert!(TestApi.cloud_is_binary_content_type("image/png; charset=binary"));
    assert!(TestApi.cloud_is_binary_content_type("audio/mpeg"));
    assert!(TestApi.cloud_is_binary_content_type("video/mp4"));
    assert!(TestApi.cloud_is_binary_content_type("application/zip"));
    assert!(TestApi.cloud_is_binary_content_type("application/gzip"));
    // Text-bearing types are NOT binary (octet-stream is treated as maybe-text
    // elsewhere, so it must not be flagged binary here).
    assert!(!TestApi.cloud_is_binary_content_type("text/plain; charset=utf-8"));
    assert!(!TestApi.cloud_is_binary_content_type("application/json"));
    assert!(!TestApi.cloud_is_binary_content_type("application/octet-stream"));
}

// ==========================================================================
// Endpoint googleapis.com match (gates ambient bearer-token forwarding)
// ==========================================================================

#[test]
fn endpoint_is_google_accepts_googleapis_hosts() {
    assert!(TestApi.gcs_endpoint_is_google("https://storage.googleapis.com"));
    assert!(TestApi.gcs_endpoint_is_google("https://www.googleapis.com/storage/v1"));
    // Bare apex, matched case-insensitively.
    assert!(TestApi.gcs_endpoint_is_google("https://GoogleAPIs.com"));
}

#[test]
fn endpoint_is_google_rejects_non_google_and_spoofed_hosts() {
    // An unrelated host.
    assert!(!TestApi.gcs_endpoint_is_google("https://storage.example.com"));
    // Suffix-spoof: googleapis.com is a *label prefix* of an attacker domain,
    // not a parent domain -> must NOT match.
    assert!(!TestApi.gcs_endpoint_is_google("https://googleapis.com.evil.example"));
    // Substring-spoof.
    assert!(!TestApi.gcs_endpoint_is_google("https://notgoogleapis.com"));
    // Malformed endpoint is fail-closed as non-Google (credential forwarding
    // stays disabled).
    assert!(!TestApi.gcs_endpoint_is_google("not a url"));
    assert!(!TestApi.gcs_endpoint_is_google(""));
}

#[test]
fn credential_forward_is_caller_explicit_only() {
    // The token-forwarding policy is exactly the explicit flag: no env var or
    // hidden default can weaken it.
    assert!(TestApi.gcs_credential_forward_allowed(true));
    assert!(!TestApi.gcs_credential_forward_allowed(false));
}

// ==========================================================================
// Endpoint SSRF refusal (reuses keyhog_verifier::ssrf), hermetic, no network
// ==========================================================================

#[test]
fn loopback_ipv4_endpoint_is_refused() {
    let error = single_endpoint_error("http://127.0.0.1");
    assert!(
        error.contains(GCS_SSRF_REFUSAL),
        "127.0.0.1 loopback must be refused with the SSRF host reason, got: {error}"
    );
}

#[test]
fn gcp_metadata_ip_endpoint_is_refused() {
    // 169.254.169.254 is the link-local cloud-metadata (IMDS) endpoint.
    let error = single_endpoint_error("http://169.254.169.254");
    assert!(
        error.contains(GCS_SSRF_REFUSAL),
        "IMDS metadata IP must be refused with the SSRF host reason, got: {error}"
    );
}

#[test]
fn ipv6_loopback_endpoint_is_refused() {
    let error = single_endpoint_error("https://[::1]");
    assert!(
        error.contains(GCS_SSRF_REFUSAL),
        "IPv6 loopback [::1] must be refused with the SSRF host reason, got: {error}"
    );
}

#[test]
fn ssrf_refusal_is_source_error_other_with_full_wrapper() {
    // Proves the refusal surfaces as `SourceError::Other`, whose Display wraps
    // the reason with the operator-facing "Fix:" guidance (the exact bytes).
    let error = single_endpoint_error("http://10.0.0.5");
    assert_eq!(
        error,
        format!(
            "failed to read source: {GCS_SSRF_REFUSAL}. \
Fix: adjust the source settings or input so KeyHog can read plain text safely"
        ),
        "SSRF refusal must be a SourceError::Other with the exact wrapped message"
    );
}

#[test]
fn non_http_scheme_endpoint_is_invalid_not_ssrf() {
    // An `ftp://` endpoint is refused by the scheme gate, not the host screen,
    // so the message is the generic invalid-endpoint form (no "(SSRF)").
    let error = single_endpoint_error("ftp://storage.example.com");
    assert!(
        error.contains("invalid GCS endpoint") && !error.contains("(SSRF)"),
        "ftp scheme must be refused as an invalid GCS endpoint, got: {error}"
    );
}

#[test]
fn userinfo_bearing_endpoint_is_invalid() {
    // Embedded credentials (`user:pass@host`) are refused by the userinfo gate.
    let error = single_endpoint_error("https://user:pass@storage.example.com");
    assert!(
        error.contains("invalid GCS endpoint"),
        "userinfo-bearing endpoint must be refused as invalid, got: {error}"
    );
}

// ==========================================================================
// Malformed bucket names, exact error strings (hermetic, pre-network)
// ==========================================================================

#[test]
fn too_short_bucket_is_refused_with_length_error() {
    let error = single_bucket_error("ab");
    assert!(
        error.contains("invalid GCS bucket name length"),
        "a 2-char bucket must be refused for length, got: {error}"
    );
}

#[test]
fn bucket_with_slash_is_refused() {
    let error = single_bucket_error("bad/bucket");
    assert!(
        error.contains("invalid GCS bucket 'bad/bucket'"),
        "a slash-bearing bucket must be refused by name, got: {error}"
    );
}

#[test]
fn uppercase_bucket_is_refused() {
    let error = single_bucket_error("MyBucket");
    assert!(
        error.contains("invalid GCS bucket 'MyBucket'"),
        "an uppercase bucket must be refused (GCS names are lowercase), got: {error}"
    );
}

#[test]
fn bucket_with_dot_dot_is_refused() {
    // `..` is a path-traversal token; refused before it can reach a URL.
    let error = single_bucket_error("a..b");
    assert!(
        error.contains("invalid GCS bucket 'a..b'"),
        "a `..`-bearing bucket must be refused by name, got: {error}"
    );
}

// ==========================================================================
// Listing entry -> exact chunk metadata (mock server, loopback opt-in)
// ==========================================================================

#[test]
fn listed_object_maps_to_exact_gs_path_and_metadata() {
    let server = httpmock::MockServer::start();
    let list_body = r#"{"items":[{"name":"logs/app.log","size":"42"}]}"#;
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(list_body);
    });
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/logs/app.log"))
            .query_param("alt", "media");
        then.status(200)
            .header("content-type", "text/plain")
            .body("plain config text value\n");
    });

    let endpoint = server.url("");
    let source = TestApi.gcs_source_with_endpoint(BUCKET, endpoint);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert_eq!(
        errors.len(),
        0,
        "a listed text object must not produce an error row; got {} error(s)",
        errors.len()
    );
    assert_eq!(chunks.len(), 1, "one listed object -> exactly one chunk");

    let meta = &chunks[0].metadata;
    // The gs:// display path is bucket + object key, exactly.
    assert_eq!(
        meta.path.as_deref(),
        Some("gs://keyhog-gcs-classify/logs/app.log"),
        "chunk path must be the exact gs:// URI for the listed object"
    );
    assert_eq!(
        meta.source_type.as_ref(),
        "gcs",
        "source_type must be \"gcs\""
    );
    // size_bytes carries the LISTED size (42), not the downloaded body length.
    assert_eq!(
        meta.size_bytes,
        Some(42),
        "size_bytes must be the listed object size"
    );
    assert_eq!(meta.base_offset, 0, "whole-object chunk starts at offset 0");
    assert_eq!(meta.base_line, 0, "whole-object chunk starts at line 0");
    assert_eq!(meta.commit, None, "GCS objects carry no commit");
    // The chunk body is the downloaded object content.
    assert!(
        chunks[0].data.as_ref().contains("plain config text value"),
        "chunk data must carry the downloaded object body"
    );
}

#[test]
fn malformed_listed_object_size_is_exact_error() {
    let server = httpmock::MockServer::start();
    // `size` is not a base-10 integer -> `GcsObject::size_bytes` fails with a
    // named error before any object GET is issued.
    let list_body = r#"{"items":[{"name":"data.txt","size":"not-a-number"}]}"#;
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(list_body);
    });
    // Assert the object body is NEVER fetched (we error on its listed metadata).
    let object_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/data.txt"));
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let endpoint = server.url("");
    let source = TestApi.gcs_source_with_endpoint(BUCKET, endpoint);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert_eq!(chunks.len(), 0, "a size-parse failure must yield no chunk");
    assert_eq!(errors.len(), 1, "exactly one error row for the bad object");
    let message = errors[0].to_string();
    assert!(
        message.contains("failed to parse GCS object size for 'data.txt'"),
        "error must name the object whose listed size failed to parse, got: {message}"
    );
    assert_eq!(
        object_get.calls(),
        0,
        "an object with an unparseable listed size must NOT be downloaded"
    );
}
