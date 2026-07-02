//! Regression: S3 endpoint SYNTAX validation + AWS-region/host classification.
//!
//! Two pure, hermetic (no-network) surfaces are pinned here:
//!
//!   1. ENDPOINT SYNTAX. A custom `--s3-endpoint` flows through the real
//!      production path `S3Source::chunks()` -> `collect_s3_chunks` ->
//!      `build_base_url` -> `validate_endpoint` -> `cloud::parse_http_endpoint`.
//!      A malformed endpoint (wrong scheme, embedded credentials, fragment,
//!      query string, unparseable, missing scheme) is refused BEFORE any socket
//!      is opened, so the source aborts with EXACTLY ONE error row carrying the
//!      `invalid S3 endpoint` reason. Every case below fails at the URL-shape
//!      stage (scheme / userinfo / fragment) which runs before DNS, or at the
//!      `.invalid` NXDOMAIN host, so the assertions are deterministic and open
//!      no connections.
//!
//!   2. AWS-HOST CLASSIFICATION. `endpoint_is_aws` decides whether an endpoint
//!      is AWS-owned (and therefore whether ambient SigV4 credentials may be
//!      auto-forwarded). It is a HOST-only, scheme-agnostic, registrable-suffix
//!      match against `amazonaws.com` / `amazonaws.com.cn`. The adversarial
//!      cases here (domain-in-path, domain-in-userinfo, apex, no-dot boundary,
//!      trailing-dot FQDN, port) fail CLOSED to non-AWS when the host is not a
//!      genuine `amazonaws.com` subdomain.
//!
//! Distinct from `regression_s3_key_listing.rs` (iter9), which covers regional
//! host recognition and object-key classification via a mock listing server:
//! this file owns the endpoint-SYNTAX refusal path and the host-match EDGE
//! cases (path/userinfo confusion, apex, boundary, FQDN dot, port).

#![cfg(feature = "s3")]

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};

/// A syntactically valid S3 bucket name (3-63 chars, lowercase/digit/dash, no
/// leading/trailing dash, no `..`) so `validate_bucket_name` passes and
/// execution reaches the endpoint validation stage.
const BUCKET: &str = "keyhog-region-bucket";

/// The load-bearing refusal substring emitted by `validate_endpoint` /
/// `parse_http_endpoint` for a malformed S3 endpoint. `SourceError::Other`
/// wraps it as `failed to read source: invalid S3 endpoint. Fix: ...`, so a
/// substring match is stable against the surrounding boilerplate.
const INVALID_ENDPOINT: &str = "invalid S3 endpoint";

/// Drive the REAL `S3Source::chunks()` production path for a custom `endpoint`
/// and return the single error-row message. A malformed endpoint aborts the
/// source before listing, yielding EXACTLY ONE `Err` row; this asserts that
/// shape too (a scanned `Ok` chunk means the endpoint was wrongly accepted).
fn single_endpoint_error(endpoint: &str) -> String {
    let source = TestApi.s3_source_with_endpoint(BUCKET, endpoint);
    let rows: Vec<_> = source.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "a malformed S3 endpoint must abort with exactly one error row before \
         listing; got {} row(s) for endpoint {endpoint}",
        rows.len()
    );
    match &rows[0] {
        Ok(chunk) => panic!(
            "endpoint {endpoint} must be REFUSED, but the source yielded a \
             scanned chunk with metadata {:?}",
            chunk.metadata
        ),
        Err(error) => error.to_string(),
    }
}

// ---------------------------------------------------------------------------
// (1) Endpoint SYNTAX refusal — real chunks() production path, no network
// ---------------------------------------------------------------------------

#[test]
fn custom_endpoint_with_query_string_is_refused() {
    // Shape (scheme/host/no-userinfo/no-fragment) passes `parse_http_endpoint`;
    // `validate_endpoint`'s own `query().is_some()` guard then rejects it. Host
    // `minio.invalid` is a guaranteed NXDOMAIN (RFC 6761), so the intervening
    // DNS screen fast-fails to "no address" and never opens a socket.
    let error = single_endpoint_error("https://minio.invalid/?list-type=2");
    assert!(
        error.contains(INVALID_ENDPOINT),
        "a query-bearing endpoint must be refused as an invalid S3 endpoint, got: {error}"
    );
}

#[test]
fn ftp_scheme_endpoint_is_refused() {
    // Only http/https are permitted; `ftp://` is rejected at the shape stage,
    // before any name resolution.
    let error = single_endpoint_error("ftp://minio.example.com");
    assert!(
        error.contains(INVALID_ENDPOINT),
        "an ftp:// endpoint must be refused as an invalid S3 endpoint, got: {error}"
    );
}

#[test]
fn endpoint_with_embedded_username_is_refused() {
    // Credentials in the endpoint URL (`user:secret@host`) are refused: a
    // non-empty username fails the shape screen before a request is built, so
    // the secret is never sent on the wire.
    let error = single_endpoint_error("https://user:secret@minio.example.com");
    assert!(
        error.contains(INVALID_ENDPOINT),
        "an endpoint with embedded userinfo must be refused, got: {error}"
    );
}

#[test]
fn endpoint_with_password_only_is_refused() {
    // The password half of userinfo is screened independently of the username:
    // `:pw@host` has an empty username but `password().is_some()`, and is still
    // refused.
    let error = single_endpoint_error("https://:pw@minio.example.com");
    assert!(
        error.contains(INVALID_ENDPOINT),
        "an endpoint with a password-only userinfo must be refused, got: {error}"
    );
}

#[test]
fn endpoint_with_fragment_is_refused() {
    // A URL fragment (`#...`) is meaningless for an S3 REST endpoint and is
    // rejected at the shape stage.
    let error = single_endpoint_error("https://minio.example.com/#frag");
    assert!(
        error.contains(INVALID_ENDPOINT),
        "an endpoint carrying a fragment must be refused, got: {error}"
    );
}

#[test]
fn unparseable_endpoint_is_refused() {
    // A string that is not a URL at all fails `reqwest::Url::parse`, surfaced as
    // `invalid S3 endpoint: <parse error>`.
    let error = single_endpoint_error("::: not a url :::");
    assert!(
        error.contains(INVALID_ENDPOINT),
        "an unparseable endpoint must be refused, got: {error}"
    );
}

#[test]
fn scheme_relative_endpoint_is_refused() {
    // A bare host with no scheme is a relative URL without a base and cannot be
    // parsed into an absolute endpoint, so it is refused.
    let error = single_endpoint_error("s3.example.com");
    assert!(
        error.contains(INVALID_ENDPOINT),
        "a scheme-less endpoint must be refused, got: {error}"
    );
}

// ---------------------------------------------------------------------------
// (2) AWS-host classification edge cases — pure `endpoint_is_aws`, no network
// ---------------------------------------------------------------------------

#[test]
fn apex_amazonaws_domains_match_exactly() {
    // The bare registrable apex (no subdomain) is AWS-owned for both the
    // commercial and China partitions.
    assert!(
        TestApi.s3_endpoint_is_aws("https://amazonaws.com"),
        "the bare amazonaws.com apex must classify as AWS-owned"
    );
    assert!(
        TestApi.s3_endpoint_is_aws("https://amazonaws.com.cn"),
        "the bare amazonaws.com.cn China apex must classify as AWS-owned"
    );
}

#[test]
fn subdomain_boundary_requires_a_leading_dot() {
    // A single-label subdomain of the apex matches...
    assert!(
        TestApi.s3_endpoint_is_aws("https://a.amazonaws.com"),
        "a.amazonaws.com is a genuine subdomain and must classify as AWS-owned"
    );
    // ...but a host that merely ENDS in the suffix bytes without a dot boundary
    // (`notamazonaws.com`) is a different registrable domain and must fail
    // closed to non-AWS so ambient creds are not forwarded to it.
    assert!(
        !TestApi.s3_endpoint_is_aws("https://notamazonaws.com"),
        "notamazonaws.com shares suffix bytes but is not a subdomain; must be non-AWS"
    );
}

#[test]
fn amazonaws_domain_in_path_is_ignored() {
    // The classifier keys on the HOST, never the path. A third-party host with
    // `amazonaws.com` sitting in the path is non-AWS.
    assert!(
        !TestApi.s3_endpoint_is_aws("https://minio.example.org/amazonaws.com/bucket"),
        "amazonaws.com in the URL path must not make a non-AWS host classify as AWS"
    );
}

#[test]
fn amazonaws_domain_in_userinfo_is_ignored() {
    // `s3.amazonaws.com@evil.example.org` resolves to HOST `evil.example.org`;
    // the userinfo half is attacker-controlled decoration and must not smuggle
    // AWS-owned classification (which would forward ambient SigV4 creds to the
    // attacker's host).
    assert!(
        !TestApi.s3_endpoint_is_aws("https://s3.amazonaws.com@evil.example.org"),
        "amazonaws.com in userinfo must not make evil.example.org classify as AWS"
    );
}

#[test]
fn classification_is_scheme_agnostic_and_host_driven() {
    // `endpoint_is_aws` screens only the host, independent of scheme (scheme is
    // enforced separately by `validate_endpoint`). Both http and ftp forms of a
    // genuine AWS host classify as AWS-owned.
    assert!(
        TestApi.s3_endpoint_is_aws("http://s3.amazonaws.com"),
        "an http:// AWS host must classify as AWS-owned"
    );
    assert!(
        TestApi.s3_endpoint_is_aws("ftp://s3.amazonaws.com"),
        "the host-only classifier must ignore scheme: ftp:// AWS host is still AWS-owned"
    );
}

#[test]
fn regional_host_with_explicit_port_still_matches() {
    // An explicit `:443` port is not part of `host_str()`, so a regional
    // endpoint with a port still classifies as AWS-owned.
    assert!(
        TestApi.s3_endpoint_is_aws("https://my-bucket.s3.us-east-1.amazonaws.com:443"),
        "an explicit port must not defeat the AWS host match"
    );
}

#[test]
fn raw_ip_literal_endpoint_is_never_aws_owned() {
    // A raw IP-literal endpoint has no `amazonaws.com` registrable suffix, so it
    // fails closed to non-AWS: ambient SigV4 credentials are never auto-forwarded
    // to a bare IP host. 192.0.2.10 is TEST-NET-1 (RFC 5737) and never resolves
    // anywhere, so no network is touched by the pure classifier.
    assert!(
        !TestApi.s3_endpoint_is_aws("https://192.0.2.10"),
        "a raw IP-literal endpoint must classify as non-AWS"
    );
    // The hyphen-boundary confusion `s3-amazonaws.com` is a distinct registrable
    // domain (no dot before the suffix) and must also fail closed.
    assert!(
        !TestApi.s3_endpoint_is_aws("https://s3-amazonaws.com"),
        "s3-amazonaws.com has no dot boundary before the suffix; must be non-AWS"
    );
}
