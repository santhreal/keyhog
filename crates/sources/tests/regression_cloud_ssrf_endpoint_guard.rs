//! Regression: cloud object-storage SSRF endpoint host-screen.
//!
//! `cloud::parse_http_endpoint` (shared by the S3, GCS, and Azure Blob source
//! backends) used to validate only scheme / userinfo / fragment shape. An
//! operator-supplied custom endpoint pointing at a private, loopback,
//! link-local, or cloud-metadata address (`--s3-endpoint http://169.254.169.254`,
//! `http://127.0.0.1`, `http://10.0.0.5`, `https://[::1]`,
//! `https://metadata.google.internal`) therefore turned the scanner into an
//! SSRF proxy for internal services, and the blocking client's auto-follow
//! redirect policy let a hostile endpoint bounce a request to such a host after
//! the fact.
//!
//! The fix screens the endpoint host against the fleet-canonical
//! `keyhog_verifier::ssrf::is_private_url` classifier before a request is ever
//! built, and disables redirect-following on the cloud blocking client. These
//! tests drive the REAL public `S3Source::chunks()` production path so they
//! exercise `parse_http_endpoint` end to end.
//!
//! Every SSRF-refused endpoint fails inside `build_base_url` -> `validate_endpoint`
//! -> `parse_http_endpoint` BEFORE any socket is opened, so the assertions are
//! hermetic (no network, no mock server) and deterministic.

#![cfg(feature = "s3")]

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};

/// A syntactically valid S3 bucket name (3-63 chars, lowercase/digit/dash, no
/// leading/trailing dash) so `validate_bucket_name` passes and execution
/// reaches the endpoint host-screen.
const BUCKET: &str = "keyhog-ssrf-bucket";

/// Drive `S3Source::chunks()` for a custom `endpoint` and return the single
/// error message string. An SSRF-refused endpoint yields exactly one error row
/// (the source aborts before listing), so this asserts that shape too.
fn single_endpoint_error(endpoint: &str) -> String {
    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, endpoint)
        .chunks()
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "an SSRF-refused endpoint must abort with exactly one error row before listing; \
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

/// The exact SSRF-refusal substring emitted for a private/loopback/link-local/
/// metadata host (`source` == "S3" here). This is the load-bearing contract:
/// the refusal is host-based, not a generic "invalid endpoint".
const SSRF_REFUSAL: &str =
    "refusing S3 endpoint: host is a private, loopback, link-local, or cloud-metadata address (SSRF)";

// --------------------------------------------------------------------------
// Private / loopback / link-local / metadata literal IP endpoints — REJECTED
// --------------------------------------------------------------------------

#[test]
fn aws_metadata_service_ipv4_endpoint_is_refused() {
    // 169.254.169.254 is the IMDS link-local metadata endpoint — the canonical
    // cloud SSRF target.
    let error = single_endpoint_error("http://169.254.169.254");
    assert!(
        error.contains(SSRF_REFUSAL),
        "IMDS metadata IP must be refused with the SSRF host reason, got: {error}"
    );
}

#[test]
fn loopback_ipv4_endpoint_is_refused() {
    let error = single_endpoint_error("http://127.0.0.1");
    assert!(
        error.contains(SSRF_REFUSAL),
        "127.0.0.1 loopback must be refused with the SSRF host reason, got: {error}"
    );
}

#[test]
fn loopback_ipv4_with_port_endpoint_is_refused() {
    // A non-default port must not smuggle the loopback host past the screen.
    let error = single_endpoint_error("http://127.0.0.1:9000");
    assert!(
        error.contains(SSRF_REFUSAL),
        "127.0.0.1:9000 must be refused with the SSRF host reason, got: {error}"
    );
}

#[test]
fn private_10_range_endpoint_is_refused() {
    let error = single_endpoint_error("https://10.0.0.5");
    assert!(
        error.contains(SSRF_REFUSAL),
        "RFC1918 10.0.0.5 must be refused with the SSRF host reason, got: {error}"
    );
}

#[test]
fn private_172_16_range_endpoint_is_refused() {
    // Low edge of the 172.16.0.0/12 RFC1918 block.
    let error = single_endpoint_error("https://172.16.0.1");
    assert!(
        error.contains(SSRF_REFUSAL),
        "RFC1918 172.16.0.1 must be refused with the SSRF host reason, got: {error}"
    );
}

#[test]
fn private_192_168_range_endpoint_is_refused() {
    let error = single_endpoint_error("https://192.168.1.1");
    assert!(
        error.contains(SSRF_REFUSAL),
        "RFC1918 192.168.1.1 must be refused with the SSRF host reason, got: {error}"
    );
}

#[test]
fn ipv6_loopback_endpoint_is_refused() {
    let error = single_endpoint_error("https://[::1]");
    assert!(
        error.contains(SSRF_REFUSAL),
        "IPv6 loopback [::1] must be refused with the SSRF host reason, got: {error}"
    );
}

// --------------------------------------------------------------------------
// Metadata / internal *hostnames* (DNS-name form, not literal IP) — REJECTED
// --------------------------------------------------------------------------

#[test]
fn gcp_metadata_hostname_endpoint_is_refused() {
    // metadata.google.internal ends in `.internal`, a name the classifier
    // refuses because it is never publicly routable.
    let error = single_endpoint_error("https://metadata.google.internal");
    assert!(
        error.contains(SSRF_REFUSAL),
        "metadata.google.internal must be refused with the SSRF host reason, got: {error}"
    );
}

#[test]
fn localhost_hostname_endpoint_is_refused() {
    let error = single_endpoint_error("http://localhost:8080");
    assert!(
        error.contains(SSRF_REFUSAL),
        "localhost must be refused with the SSRF host reason, got: {error}"
    );
}

// --------------------------------------------------------------------------
// Integer/hex-encoded loopback evasion forms — REJECTED
// --------------------------------------------------------------------------

#[test]
fn decimal_encoded_loopback_endpoint_is_refused() {
    // http://2130706433 == 127.0.0.1 under permissive resolvers; the classifier
    // refuses dotless-integer hosts (VRF-class SSRF bypass).
    let error = single_endpoint_error("http://2130706433");
    assert!(
        error.contains(SSRF_REFUSAL),
        "decimal-encoded loopback 2130706433 must be refused, got: {error}"
    );
}

#[test]
fn hex_encoded_loopback_endpoint_is_refused() {
    // http://0x7f000001 == 127.0.0.1 under glibc getaddrinfo.
    let error = single_endpoint_error("http://0x7f000001");
    assert!(
        error.contains(SSRF_REFUSAL),
        "hex-encoded loopback 0x7f000001 must be refused, got: {error}"
    );
}

// --------------------------------------------------------------------------
// Scheme / userinfo shape rejections — REJECTED with the generic reason
// (pre-existing gate; asserted here so the SSRF change did not regress it)
// --------------------------------------------------------------------------

#[test]
fn non_http_scheme_endpoint_is_refused() {
    // An `ftp://` endpoint is refused by the scheme gate, not the host screen,
    // so the message is the generic invalid-endpoint form.
    let error = single_endpoint_error("ftp://s3.example.com");
    assert!(
        error.contains("invalid S3 endpoint") && !error.contains("(SSRF)"),
        "ftp scheme must be refused as an invalid endpoint, got: {error}"
    );
}

#[test]
fn file_scheme_endpoint_is_refused() {
    let error = single_endpoint_error("file:///etc/passwd");
    assert!(
        error.contains("invalid S3 endpoint"),
        "file:// scheme must be refused as an invalid endpoint, got: {error}"
    );
}

#[test]
fn userinfo_password_endpoint_is_refused() {
    // Embedded credentials (`user:pass@host`) are refused by the userinfo gate.
    let error = single_endpoint_error("https://user:pass@s3.example.com");
    assert!(
        error.contains("invalid S3 endpoint"),
        "userinfo-bearing endpoint must be refused as invalid, got: {error}"
    );
}

#[test]
fn userinfo_username_only_endpoint_is_refused() {
    let error = single_endpoint_error("https://attacker@s3.example.com");
    assert!(
        error.contains("invalid S3 endpoint"),
        "username-only userinfo endpoint must be refused as invalid, got: {error}"
    );
}

// --------------------------------------------------------------------------
// SourceError variant / full message shape
// --------------------------------------------------------------------------

#[test]
fn ssrf_refusal_is_a_source_error_other_with_full_wrapper() {
    // Proves the refusal surfaces as `SourceError::Other`, whose Display wraps
    // the reason with the operator-facing "Fix:" guidance.
    let error = single_endpoint_error("http://169.254.169.254");
    assert_eq!(
        error,
        format!(
            "failed to read source: {SSRF_REFUSAL}. \
Fix: adjust the source settings or input so KeyHog can read plain text safely"
        ),
        "SSRF refusal must be a SourceError::Other with the exact wrapped message"
    );
}

// --------------------------------------------------------------------------
// Negative twin: a normal public HTTPS host is ACCEPTED by the SSRF guard
// --------------------------------------------------------------------------

#[test]
fn public_https_host_endpoint_is_accepted_by_the_ssrf_guard() {
    // `.invalid` is an RFC 6761 reserved TLD: the classifier treats it as an
    // ordinary (non-private) domain, so `parse_http_endpoint` returns Ok and
    // execution proceeds past validation to DNS resolution, which fails fast
    // with NXDOMAIN. The point is that the failure is a network/DNS error, NOT
    // an SSRF refusal or an invalid-endpoint rejection — proving a legitimate
    // public host passes the guard.
    let rows: Vec<_> = TestApi
        .s3_source_with_endpoint(BUCKET, "https://objectstore.public.invalid")
        .chunks()
        .collect();
    for row in &rows {
        if let Err(error) = row {
            let message = error.to_string();
            assert!(
                !message.contains("(SSRF)"),
                "a public host must NOT be rejected by the SSRF guard, got: {message}"
            );
            assert!(
                !message.contains("invalid S3 endpoint"),
                "a public host must NOT be rejected as an invalid endpoint, got: {message}"
            );
        }
    }
}
