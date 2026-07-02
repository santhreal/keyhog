//! Regression coverage for the *pure* Azure Blob classification decisions and
//! the SSRF endpoint screen that gate whether a listed blob is downloaded and
//! scanned as text.
//!
//! Scope is deliberately narrow and host-independent: every assertion is a pure
//! function of its input (object key / content-type / endpoint string) and
//! never depends on an accelerator, network, or DNS being reachable. The
//! end-to-end `AzureBlobSource::chunks()` cases all exercise refusals that
//! short-circuit inside `validate_container_url` -> `parse_http_endpoint`
//! BEFORE any HTTP client is built or any address is resolved, so they are
//! deterministic offline.
//!
//! Self-gated at crate scope on the `azure` feature so the auto-discovered test
//! compiles to nothing (0 tests) under the default feature set and only pulls
//! in the azure symbols / `keyhog_verifier` SSRF classifier when that feature
//! is active. Registering an explicit `[[test]]` entry with
//! `required-features = ["azure"]` (mirroring the sibling azure tests) is the
//! canonical way to also skip it under a bare `cargo test`.
#![cfg(feature = "azure")]

use keyhog_core::{Source, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::AzureBlobSource;

// ---------------------------------------------------------------------------
// Pure blob-key text/binary classification (is_probably_text_object_key).
// Drives `download_azure_blob_listing_page`'s decision to scan vs. skip a blob.
// ---------------------------------------------------------------------------

#[test]
fn text_object_keys_are_scanned() {
    let api = TestApi;
    // Realistic Azure blob names an operator would want scanned for secrets.
    assert_eq!(
        api.cloud_is_probably_text_object_key("config/app.env"),
        true
    );
    assert_eq!(
        api.cloud_is_probably_text_object_key("tenant-1/secrets.txt"),
        true
    );
    assert_eq!(api.cloud_is_probably_text_object_key("app.json"), true);
    assert_eq!(api.cloud_is_probably_text_object_key("deploy.yaml"), true);
}

#[test]
fn container_and_archive_extension_keys_are_refused_as_binary() {
    let api = TestApi;
    // Extensions in the cloud BINARY_OBJECT_EXTS denylist: never text.
    assert_eq!(
        api.cloud_is_probably_text_object_key("backups/db.zip"),
        false
    );
    assert_eq!(api.cloud_is_probably_text_object_key("archive.tar"), false);
    assert_eq!(api.cloud_is_probably_text_object_key("logs.gz"), false);
    assert_eq!(api.cloud_is_probably_text_object_key("bundle.7z"), false);
    assert_eq!(api.cloud_is_probably_text_object_key("report.pdf"), false);
}

#[test]
fn default_skip_extension_image_keys_are_refused() {
    let api = TestApi;
    // Extensions owned by the Tier-B default-excludes denylist (images/binaries).
    assert_eq!(
        api.cloud_is_probably_text_object_key("assets/logo.png"),
        false
    );
    assert_eq!(api.cloud_is_probably_text_object_key("photo.jpeg"), false);
    assert_eq!(api.cloud_is_probably_text_object_key("app.wasm"), false);
    assert_eq!(api.cloud_is_probably_text_object_key("lib.so"), false);
}

#[test]
fn keys_without_extension_default_to_text() {
    let api = TestApi;
    // No `.` in the final path segment => no extension => scanned as text.
    assert_eq!(api.cloud_is_probably_text_object_key("README"), true);
    assert_eq!(api.cloud_is_probably_text_object_key("data/dump"), true);
    assert_eq!(api.cloud_is_probably_text_object_key("Dockerfile"), true);
}

#[test]
fn dotfile_and_empty_extension_boundaries_are_text() {
    let api = TestApi;
    // ".env" => empty stem => cloud_key_extension returns None => text.
    assert_eq!(api.cloud_is_probably_text_object_key(".env"), true);
    // Trailing-dot key => empty extension => None => text.
    assert_eq!(api.cloud_is_probably_text_object_key("weird."), true);
    // Bare dotfile with no stem.
    assert_eq!(api.cloud_is_probably_text_object_key(".gitignore"), true);
}

#[test]
fn extension_classification_is_ascii_case_insensitive() {
    let api = TestApi;
    // Uppercase binary extension still refused; uppercase text extension kept.
    assert_eq!(api.cloud_is_probably_text_object_key("IMAGE.PNG"), false);
    assert_eq!(api.cloud_is_probably_text_object_key("DB.ZIP"), false);
    assert_eq!(api.cloud_is_probably_text_object_key("notes.TXT"), true);
    assert_eq!(api.cloud_is_probably_text_object_key("Config.JSON"), true);
}

// ---------------------------------------------------------------------------
// Pure content-type binary classification (is_binary_content_type).
// Drives the listing-reported content-type skip in the download page.
// ---------------------------------------------------------------------------

#[test]
fn binary_content_types_are_refused() {
    let api = TestApi;
    assert_eq!(api.cloud_is_binary_content_type("image/png"), true);
    assert_eq!(api.cloud_is_binary_content_type("audio/mpeg"), true);
    assert_eq!(api.cloud_is_binary_content_type("video/mp4"), true);
    assert_eq!(api.cloud_is_binary_content_type("application/zip"), true);
    assert_eq!(api.cloud_is_binary_content_type("application/gzip"), true);
}

#[test]
fn content_type_classification_strips_params_and_folds_case() {
    let api = TestApi;
    // Parameters after `;` are dropped before matching the media type.
    assert_eq!(
        api.cloud_is_binary_content_type("image/png; charset=binary"),
        true
    );
    // Case-insensitive prefix match on the media type.
    assert_eq!(api.cloud_is_binary_content_type("IMAGE/JPEG"), true);
    // A text media type with a charset parameter is NOT binary.
    assert_eq!(
        api.cloud_is_binary_content_type("text/plain; charset=utf-8"),
        false
    );
}

#[test]
fn octet_stream_and_text_content_types_are_not_binary_classified() {
    let api = TestApi;
    // Negative twin: octet-stream is the *unknown* class, NOT the binary class
    // that `is_binary_content_type` rejects — it must return false here.
    assert_eq!(
        api.cloud_is_binary_content_type("application/octet-stream"),
        false
    );
    assert_eq!(api.cloud_is_binary_content_type("application/json"), false);
    assert_eq!(api.cloud_is_binary_content_type("text/csv"), false);
    assert_eq!(api.cloud_is_binary_content_type("text/plain"), false);
}

// ---------------------------------------------------------------------------
// SSRF endpoint classifier (keyhog_verifier::ssrf) — the single owner the
// Azure container-URL screen delegates to. Pure string classification, no DNS.
// ---------------------------------------------------------------------------

#[test]
fn ssrf_classifier_blocks_loopback_and_metadata_hosts() {
    assert_eq!(
        keyhog_verifier::ssrf::is_private_url("http://127.0.0.1/mycontainer"),
        true
    );
    assert_eq!(
        keyhog_verifier::ssrf::is_private_url("http://169.254.169.254/mycontainer"),
        true
    );
    assert_eq!(
        keyhog_verifier::ssrf::is_private_url("http://[::1]/mycontainer"),
        true
    );
    assert_eq!(
        keyhog_verifier::ssrf::is_private_url("http://10.0.0.5/mycontainer"),
        true
    );
}

#[test]
fn ssrf_classifier_allows_public_azure_blob_endpoint() {
    // Negative twin: a legitimate public Azure Blob container host is allowed.
    // A `Domain` host is classified purely (no DNS) — public => false.
    assert_eq!(
        keyhog_verifier::ssrf::is_private_url("https://acct.blob.core.windows.net/mycontainer"),
        false
    );
}

#[test]
fn ssrf_classifier_blocks_evasion_encodings_and_fails_closed() {
    // Decimal-integer-encoded 127.0.0.1.
    assert_eq!(
        keyhog_verifier::ssrf::is_private_url("http://2130706433/c"),
        true
    );
    // `.internal` suffix (GCP metadata style).
    assert_eq!(
        keyhog_verifier::ssrf::is_private_url("http://metadata.google.internal/c"),
        true
    );
    // Non-http(s) scheme fails closed (blocked).
    assert_eq!(
        keyhog_verifier::ssrf::is_private_url("ftp://acct.blob.core.windows.net/c"),
        true
    );
    // Unparseable URL fails closed (blocked).
    assert_eq!(keyhog_verifier::ssrf::is_private_url("not a url"), true);
}

// ---------------------------------------------------------------------------
// End-to-end refusal through the public Source::chunks() surface. Each of these
// short-circuits inside validate_container_url BEFORE any HTTP/DNS, yielding
// exactly one error chunk — a fail-closed refusal, never a silent degrade.
// ---------------------------------------------------------------------------

fn only_error(url: &str) -> String {
    let source = AzureBlobSource::new(url);
    let results: Vec<Result<keyhog_core::Chunk, SourceError>> = source.chunks().collect();
    assert_eq!(
        results.len(),
        1,
        "expected exactly one (error) chunk for {url}, got {}",
        results.len()
    );
    let err = results[0]
        .as_ref()
        .err()
        .expect("expected the single chunk to be an error");
    match err {
        SourceError::Other(message) => message.clone(),
        other => panic!("expected SourceError::Other for {url}, got {other:?}"),
    }
}

#[test]
fn chunks_refuses_loopback_container_as_ssrf() {
    let message = only_error("http://127.0.0.1/mycontainer");
    assert!(
        message.contains("SSRF"),
        "loopback refusal message must name SSRF, got: {message}"
    );
    assert!(
        message.contains("private"),
        "loopback refusal message must name the private class, got: {message}"
    );
    assert!(
        message.contains("Azure Blob container URL"),
        "refusal must name the Azure Blob container URL source, got: {message}"
    );
}

#[test]
fn chunks_refuses_cloud_metadata_container_as_ssrf() {
    let message = only_error("http://169.254.169.254/mycontainer");
    assert!(
        message.contains("SSRF"),
        "metadata refusal message must name SSRF, got: {message}"
    );
    assert!(
        message.contains("cloud-metadata"),
        "metadata refusal must name the cloud-metadata class, got: {message}"
    );
}

#[test]
fn chunks_refuses_userinfo_and_non_http_scheme_endpoints() {
    // Credentials embedded in the URL are refused before any request is built.
    let userinfo = only_error("https://user:secret@acct.blob.core.windows.net/mycontainer");
    assert!(
        userinfo.contains("invalid Azure Blob container URL endpoint"),
        "userinfo URL must be refused as an invalid endpoint, got: {userinfo}"
    );
    // A non-http(s) scheme is rejected by the shape gate before DNS.
    let scheme = only_error("ftp://acct.blob.core.windows.net/mycontainer");
    assert!(
        scheme.contains("invalid Azure Blob container URL endpoint"),
        "ftp scheme must be refused as an invalid endpoint, got: {scheme}"
    );
}

#[test]
fn chunks_reports_malformed_url_as_invalid_endpoint() {
    let message = only_error("notaurl");
    assert!(
        message.contains("invalid Azure Blob container URL endpoint"),
        "malformed URL must be refused as an invalid endpoint, got: {message}"
    );
}
