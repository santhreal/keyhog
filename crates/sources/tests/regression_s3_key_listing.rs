//! LANE sources-deep regression: the S3 key-listing building blocks that sit
//! UNDER the `S3Source::chunks()` pagination loop (`s3/mod.rs` +
//! `cloud/mod.rs`) must each be exact and host-independent:
//!
//!   * ENDPOINT/REGION RECOGNITION — `endpoint_is_aws` decides whether an
//!     `--s3-endpoint` (regional / dual-stack / China-partition host) is
//!     AWS-owned, so ambient `AWS_ACCESS_KEY_ID` SigV4 signing is scoped to AWS
//!     hosts only. Suffix-confusion hosts (`evil-amazonaws.com`,
//!     `amazonaws.com.attacker.net`) and unparseable endpoints must be rejected.
//!   * OBJECT-KEY CLASSIFICATION — `is_probably_text_object_key` decides which
//!     listed keys are downloaded and scanned as text vs. dropped as
//!     binary/container content; the decision is by extension, case-insensitive,
//!     with dot-files / no-extension keys treated as text.
//!   * MALFORMED BUCKET => EXACT ERROR — `collect_s3_chunks` validates the
//!     bucket name BEFORE any network call, so an invalid bucket yields exactly
//!     one `SourceError::Other` whose message names the exact refusal (no HTTP
//!     request is ever issued; fully offline / host-independent).
//!   * CONTINUATION TOKEN DRIVES THE NEXT PAGE — a truncated page's
//!     `NextContinuationToken` (even one carrying URL-special bytes `=`/`/`/`+`)
//!     is threaded VERBATIM into the page-2 `continuation-token` query param; a
//!     NON-truncated page never triggers a second listing even if it carries a
//!     stray token (pagination is gated on `IsTruncated`, not token presence).
//!
//! These are DISTINCT from `regression_s3_listing_pagination.rs` (which drives
//! the multi-page union count + per-object skip counters): this file pins the
//! pure classifiers/validators and the token-encoding/gating edge cases.
//!
//! HOST-INDEPENDENCE: no accelerator is touched. The classifier/validator tests
//! are pure and offline. The two token tests bind httpmock on 127.0.0.1 (opting
//! into the loud, default-off private-endpoint allowance) and force the
//! anonymous S3 path by clearing ambient AWS credentials under a file-local
//! lock, so the result never depends on the host's AWS env.

#![cfg(feature = "s3")]

mod support;

use keyhog_core::{Source, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::sync::{Mutex, MutexGuard};
use support::split_chunk_results;

const BUCKET: &str = "regression-key-bucket";
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Serialize the two httpmock tests and pin their process env: allow the
/// 127.0.0.1 endpoint through the cloud SSRF screen and clear any ambient AWS
/// credentials so `resolve_s3_auth` takes the anonymous branch (a non-AWS
/// endpoint with ambient creds present would fail closed with an error instead).
fn anon_localhost_guard() -> MutexGuard<'static, ()> {
    let guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::env::set_var("KEYHOG_ALLOW_PRIVATE_CLOUD_ENDPOINT", "1");
    for name in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ] {
        std::env::remove_var(name);
    }
    guard
}

/// One `<Contents>` block for a ListObjectsV2 body.
fn contents(key: &str, size: u64) -> String {
    format!("<Contents><Key>{key}</Key><Size>{size}</Size></Contents>")
}

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

/// A NON-truncated page that nonetheless echoes a `NextContinuationToken`. A
/// correct paginator gates on `IsTruncated=false` and must NOT follow the token.
fn final_page_with_stray_token(objects: &str, token: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{BUCKET}</Name>
  <IsTruncated>false</IsTruncated>
  <NextContinuationToken>{token}</NextContinuationToken>
  {objects}
</ListBucketResult>"#
    )
}

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
// Endpoint / region recognition (pure, offline).
// ---------------------------------------------------------------------------

/// Regional and global AWS S3 hosts are recognized as AWS-owned so ambient
/// SigV4 auto-signing stays scoped to AWS. Region-bearing hosts count.
#[test]
fn endpoint_is_aws_recognizes_regional_and_global_hosts() {
    assert!(TestApi.s3_endpoint_is_aws("https://s3.amazonaws.com"));
    assert!(TestApi.s3_endpoint_is_aws("https://my-bucket.s3.amazonaws.com"));
    assert!(TestApi.s3_endpoint_is_aws("https://my-bucket.s3.us-west-2.amazonaws.com"));
    assert!(TestApi.s3_endpoint_is_aws("https://my-bucket.s3.eu-central-1.amazonaws.com"));
    // Host comparison is ASCII-case-insensitive.
    assert!(TestApi.s3_endpoint_is_aws("https://S3.AMAZONAWS.COM"));
}

/// Dual-stack and China-partition (`amazonaws.com.cn`) hosts are also AWS-owned.
#[test]
fn endpoint_is_aws_recognizes_dualstack_and_china_partition() {
    assert!(
        TestApi.s3_endpoint_is_aws("https://my-bucket.s3.dualstack.eu-west-1.amazonaws.com"),
        "dual-stack regional host is AWS-owned"
    );
    assert!(
        TestApi.s3_endpoint_is_aws("https://my-bucket.s3.cn-north-1.amazonaws.com.cn"),
        "China-partition host is AWS-owned"
    );
}

/// Non-AWS endpoints and suffix-confusion hosts must be rejected: the '.'
/// domain boundary is enforced, so `evil-amazonaws.com` and
/// `amazonaws.com.attacker.net` are NOT AWS. This is the credential-leak guard.
#[test]
fn endpoint_is_aws_rejects_non_aws_and_suffix_confusion() {
    assert!(
        !TestApi.s3_endpoint_is_aws("https://minio.corp.internal:9000"),
        "a self-hosted MinIO endpoint is not AWS"
    );
    assert!(
        !TestApi.s3_endpoint_is_aws("https://evil-amazonaws.com"),
        "a host that merely ends in the literal string must not match without a dot boundary"
    );
    assert!(
        !TestApi.s3_endpoint_is_aws("https://amazonaws.com.attacker.net"),
        "an attacker subdomain-prefix host must not be treated as AWS"
    );
    // A typo'd suffix falls into the non-AWS bucket (conservative on purpose).
    assert!(!TestApi.s3_endpoint_is_aws("https://bucket.s3.amazonaws.co"));
}

/// An unparseable / scheme-less endpoint fails closed (not AWS): a parse failure
/// must never be treated as an AWS host that receives ambient credentials.
#[test]
fn endpoint_is_aws_rejects_unparseable_endpoint() {
    assert!(!TestApi.s3_endpoint_is_aws("not-a-url"));
    assert!(!TestApi.s3_endpoint_is_aws(""));
    assert!(!TestApi.s3_endpoint_is_aws("http://"));
}

/// The credential-forward gate is the caller's explicit flag verbatim — no env
/// var can weaken it, so the mapping is the identity function.
#[test]
fn credential_forward_allowed_is_identity() {
    assert!(TestApi.s3_credential_forward_allowed(true));
    assert!(!TestApi.s3_credential_forward_allowed(false));
}

// ---------------------------------------------------------------------------
// Object-key classification for scanning (pure, offline).
// ---------------------------------------------------------------------------

/// Text-shaped extensions classify as scannable text objects.
#[test]
fn text_object_key_positive_scannable_extensions() {
    assert!(TestApi.cloud_is_probably_text_object_key("data/config.json"));
    assert!(TestApi.cloud_is_probably_text_object_key("logs/app.log"));
    assert!(TestApi.cloud_is_probably_text_object_key("notes.txt"));
    assert!(TestApi.cloud_is_probably_text_object_key("deploy/values.yaml"));
    assert!(TestApi.cloud_is_probably_text_object_key("keys/service.pem"));
}

/// Boundary: a dot-file (`.env`), a key with no extension, and a trailing-dot
/// key all have no usable extension and default to scannable text.
#[test]
fn text_object_key_no_extension_and_dotfile_are_scannable() {
    assert!(
        TestApi.cloud_is_probably_text_object_key(".env"),
        "a leading-dot dotfile has an empty stem => no extension => scannable"
    );
    assert!(
        TestApi.cloud_is_probably_text_object_key("secrets/production_credentials"),
        "a key with no '.' has no extension => scannable"
    );
    assert!(
        TestApi.cloud_is_probably_text_object_key("weird/trailing."),
        "a trailing-dot key has an empty extension => scannable"
    );
}

/// Container / compressed extensions are treated as binary and NOT scanned as
/// text — this is the S3-specific binary-object denylist.
#[test]
fn text_object_key_rejects_container_binary_extensions() {
    for key in [
        "backup/archive.zip",
        "dump.gz",
        "release.tgz",
        "bundle.tar",
        "vault.7z",
        "old.rar",
        "manual.pdf",
        "logs.bz2",
        "core.xz",
        "state.zst",
        "frames.lz4",
        "blob.sz",
    ] {
        assert!(
            !TestApi.cloud_is_probably_text_object_key(key),
            "container/compressed key {key} must be classified binary"
        );
    }
    // Multi-dot key resolves to its LAST extension.
    assert!(
        !TestApi.cloud_is_probably_text_object_key("archive.tar.gz"),
        "archive.tar.gz resolves to the .gz extension => binary"
    );
}

/// Default-skip binary extensions (images, native binaries, bytecode, fonts)
/// are rejected, case-insensitively.
#[test]
fn text_object_key_rejects_default_skip_extensions_case_insensitive() {
    assert!(!TestApi.cloud_is_probably_text_object_key("images/photo.png"));
    assert!(!TestApi.cloud_is_probably_text_object_key("lib/native.so"));
    assert!(!TestApi.cloud_is_probably_text_object_key("Main.class"));
    assert!(!TestApi.cloud_is_probably_text_object_key("fonts/regular.woff"));
    // Uppercase / mixed-case extensions still match the denylist.
    assert!(!TestApi.cloud_is_probably_text_object_key("tools/setup.EXE"));
    assert!(!TestApi.cloud_is_probably_text_object_key("nested/dir/backup.ZIP"));
}

/// Binary content-types (image/audio/video, zip, gzip) classify as binary, with
/// case-insensitive prefix matching and `;`-parameter stripping.
#[test]
fn binary_content_type_positive() {
    assert!(TestApi.cloud_is_binary_content_type("image/png"));
    assert!(TestApi.cloud_is_binary_content_type("audio/mpeg"));
    assert!(TestApi.cloud_is_binary_content_type("video/mp4"));
    assert!(TestApi.cloud_is_binary_content_type("application/zip"));
    assert!(TestApi.cloud_is_binary_content_type("application/gzip"));
    assert!(
        TestApi.cloud_is_binary_content_type("IMAGE/PNG"),
        "content-type prefix match is ASCII-case-insensitive"
    );
    assert!(
        TestApi.cloud_is_binary_content_type("application/zip; boundary=xyz"),
        "media-type is compared with parameters stripped"
    );
}

/// Text/structured content-types are NOT binary; `application/octet-stream` is
/// an UNKNOWN type, not part of the binary set matched here.
#[test]
fn binary_content_type_negative_and_octet_stream_excluded() {
    assert!(!TestApi.cloud_is_binary_content_type("text/plain"));
    assert!(!TestApi.cloud_is_binary_content_type("application/json"));
    assert!(!TestApi.cloud_is_binary_content_type("application/xml"));
    assert!(
        !TestApi.cloud_is_binary_content_type("application/octet-stream"),
        "octet-stream is unknown, not part of the binary content-type set"
    );
    assert!(
        !TestApi.cloud_is_binary_content_type("text/plain; charset=utf-8"),
        "a charset parameter must not flip a text media-type to binary"
    );
}

// ---------------------------------------------------------------------------
// Malformed bucket => EXACT error, offline (no HTTP request issued).
// ---------------------------------------------------------------------------

/// A too-short bucket name is refused BEFORE any listing request with the exact
/// length-error message, yielding exactly one error and zero chunks.
#[test]
fn malformed_bucket_too_short_yields_exact_length_error() {
    let source = TestApi.s3_source_with_endpoint("ab", "https://s3.amazonaws.com");
    let rows: Vec<_> = source.chunks().collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 0, "an invalid bucket yields no scanned chunk");
    assert_eq!(errors.len(), 1, "exactly one refusal error row");
    match errors[0] {
        SourceError::Other(msg) => {
            assert_eq!(msg.as_str(), "invalid S3 bucket name length");
        }
        other => panic!("expected SourceError::Other, got {other:?}"),
    }
}

/// An uppercase (non-DNS-safe) bucket name is refused with the exact
/// `invalid S3 bucket '<name>'` message, echoing the offending name verbatim.
#[test]
fn malformed_bucket_uppercase_yields_exact_invalid_error() {
    let source = TestApi.s3_source_with_endpoint("MyBucket", "https://s3.amazonaws.com");
    let rows: Vec<_> = source.chunks().collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 0);
    assert_eq!(errors.len(), 1);
    match errors[0] {
        SourceError::Other(msg) => {
            assert_eq!(msg.as_str(), "invalid S3 bucket 'MyBucket'");
        }
        other => panic!("expected SourceError::Other, got {other:?}"),
    }
    // The rendered Display carries the actionable Fix context.
    let rendered = errors[0].to_string();
    assert!(
        rendered.contains("invalid S3 bucket 'MyBucket'") && rendered.contains("Fix:"),
        "rendered error should name the bucket and a Fix, got {rendered}"
    );
}

/// A bucket name containing a consecutive-dot sequence (`..`) is refused with
/// the exact invalid-name message; the double-dot check fires before the
/// character-class check.
#[test]
fn malformed_bucket_double_dot_yields_exact_invalid_error() {
    let source = TestApi.s3_source_with_endpoint("a..b", "https://s3.amazonaws.com");
    let rows: Vec<_> = source.chunks().collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 0);
    assert_eq!(errors.len(), 1);
    match errors[0] {
        SourceError::Other(msg) => {
            assert_eq!(msg.as_str(), "invalid S3 bucket 'a..b'");
        }
        other => panic!("expected SourceError::Other, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Continuation token drives the next page (httpmock, localhost, anonymous).
// ---------------------------------------------------------------------------

/// A `NextContinuationToken` carrying URL-special bytes (`=`, `/`, `+`) — the
/// shape of a real base64 S3 cursor — must be threaded VERBATIM into the page-2
/// `continuation-token` query param. httpmock matches the DECODED param value,
/// so a page-2 hit count of exactly 1 proves the token round-tripped through
/// URL-encoding without corruption or double-encoding.
#[test]
fn continuation_token_with_url_special_chars_threaded_verbatim() {
    let _guard = anon_localhost_guard();

    let server = httpmock::MockServer::start();
    let token = "Tok/en+Value==";
    let page1 = truncated_page_with_token(&contents("a.txt", 16), token);
    let page2 = final_page(&contents("b.txt", 16));

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
            .query_param("continuation-token", token);
        then.status(200)
            .header("content-type", "application/xml")
            .body(page2);
    });
    let _a = mock_text_object(&server, "a.txt", "alpha\n");
    let _b = mock_text_object(&server, "b.txt", "bravo\n");

    let source = TestApi.s3_source_with_endpoint(BUCKET, server.url(""));
    let ok: Vec<_> = source
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("both pages of text objects must scan cleanly");

    assert_eq!(ok.len(), 2, "one object per page => exactly 2 chunks");
    let mut paths: Vec<&str> = ok
        .iter()
        .map(|c| c.metadata.path.as_deref().unwrap())
        .collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        vec!["regression-key-bucket/a.txt", "regression-key-bucket/b.txt"]
    );
    assert_eq!(list1.calls(), 1, "page 1 is the un-tokened first listing");
    assert_eq!(
        list2.calls(),
        1,
        "page 2 must be requested with the verbatim URL-special continuation token"
    );
}

/// Adversarial: a NON-truncated (`IsTruncated=false`) page that nonetheless
/// carries a stray `NextContinuationToken` must NOT trigger a second listing —
/// pagination is gated on `IsTruncated`, not on token presence. A page-2 probe
/// matching ANY continuation token must record zero calls, and the single page
/// object is still scanned.
#[test]
fn non_truncated_page_with_stray_token_makes_no_second_request() {
    let _guard = anon_localhost_guard();

    let server = httpmock::MockServer::start();
    let page1 = final_page_with_stray_token(&contents("only.txt", 16), "SHOULD-NOT-BE-FOLLOWED");

    let list1 = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_missing("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(page1);
    });
    // A page-2 request with ANY continuation token must never be issued.
    let page2_probe = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .query_param("list-type", "2")
            .query_param_exists("continuation-token");
        then.status(200)
            .header("content-type", "application/xml")
            .body(final_page(&contents("must-not-be-listed.txt", 16)));
    });
    let _obj = mock_text_object(&server, "only.txt", "only\n");

    let source = TestApi.s3_source_with_endpoint(BUCKET, server.url(""));
    let rows: Vec<_> = source.chunks().collect();
    let (ok, errors) = split_chunk_results(&rows);

    assert_eq!(ok.len(), 1, "the single page object is scanned");
    assert_eq!(
        errors.len(),
        0,
        "a clean non-truncated page is not a coverage gap"
    );
    assert_eq!(
        ok[0].metadata.path.as_deref(),
        Some("regression-key-bucket/only.txt")
    );
    assert_eq!(list1.calls(), 1, "exactly one listing request is made");
    assert_eq!(
        page2_probe.calls(),
        0,
        "a stray token on a non-truncated page must NOT drive a second listing"
    );
}
