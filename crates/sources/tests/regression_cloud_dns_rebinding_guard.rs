//! Regression: cloud object-storage SSRF **post-DNS** (rebinding) endpoint screen.
//!
//! `cloud::parse_http_endpoint` (shared by the S3, GCS, and Azure Blob backends)
//! historically screened only the *literal* endpoint host string via
//! `keyhog_verifier::ssrf::is_private_url`. Unlike `web::ssrf::resolve_and_screen`
//! (which, after the string check, ALSO resolves the host and re-screens every
//! resolved `SocketAddr` before pinning them), the cloud blocking client did NO
//! post-DNS IP re-screen. A **public hostname** whose A/AAAA record points at
//! `169.254.169.254` / `127.0.0.1` / `10.x` / `[::1]` (classic DNS rebinding)
//! therefore sailed past the string screen and connected — turning the scanner
//! into an SSRF proxy for internal / cloud-metadata services.
//!
//! The fix adds a resolve-and-veto step to `parse_http_endpoint`: after the
//! string screen it resolves the endpoint host and refuses the endpoint if ANY
//! resolved address is one the fleet-canonical
//! `keyhog_verifier::ssrf::is_private_ip_addr` classifier — the SAME predicate
//! WebSource's `resolve_and_screen` uses — rejects. The whole screen is disabled
//! per-source by the `allow_private_endpoint` Tier-A config (not env) so loopback
//! mock / self-hosted (MinIO / Ceph / httpmock) endpoints still work.
//!
//! Two kinds of coverage:
//!   * **Predicate tests** exercise the shared post-DNS screen predicate
//!     (`is_private_ip_addr`) directly on the exact resolved-address inputs a
//!     rebinding host would yield — hermetic, no DNS control needed.
//!   * **Driven-path tests** drive the real public `S3Source::chunks()`
//!     production path through `parse_http_endpoint`, asserting the literal-host
//!     screen refusal (exact message), the opt-in bypass, and that a legitimate
//!     public host is NOT refused (the resolve step fails open on NXDOMAIN).

#![cfg(feature = "s3")]

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_verifier::ssrf::is_private_ip_addr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ==========================================================================
// Group A — the shared post-DNS screen predicate, asserted directly on the
// resolved-address inputs a DNS-rebinding endpoint host would produce.
// `is_private_ip_addr` is exactly what `parse_http_endpoint`'s new
// `screen_resolved_endpoint_host` applies to each resolved `SocketAddr`.
// ==========================================================================

#[test]
fn resolved_loopback_ipv4_is_screened_as_private() {
    // attacker.example -> 127.0.0.1 (the canonical rebinding payload).
    assert!(
        is_private_ip_addr(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        "127.0.0.1 resolved from a public host must be vetoed as private"
    );
}

#[test]
fn resolved_imds_metadata_ipv4_is_screened_as_private() {
    // 169.254.169.254 is the AWS/GCP IMDS link-local metadata endpoint.
    assert!(
        is_private_ip_addr(&IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))),
        "IMDS 169.254.169.254 must be vetoed as link-local metadata"
    );
}

#[test]
fn resolved_rfc1918_ten_slash_eight_is_screened_as_private() {
    assert!(
        is_private_ip_addr(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
        "RFC1918 10.0.0.5 must be vetoed as private"
    );
}

#[test]
fn resolved_rfc1918_172_16_is_screened_as_private() {
    // Low edge of 172.16.0.0/12.
    assert!(
        is_private_ip_addr(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
        "RFC1918 172.16.0.1 must be vetoed as private"
    );
}

#[test]
fn resolved_rfc1918_192_168_is_screened_as_private() {
    assert!(
        is_private_ip_addr(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        "RFC1918 192.168.1.1 must be vetoed as private"
    );
}

#[test]
fn resolved_unspecified_ipv4_is_screened_as_private() {
    // 0.0.0.0 (INADDR_ANY) routes to the local host on many stacks — a rebind
    // to it is an SSRF vector, so the canonical classifier vetoes it.
    assert!(
        is_private_ip_addr(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
        "unspecified 0.0.0.0 must be vetoed"
    );
}

#[test]
fn resolved_ipv6_loopback_is_screened_as_private() {
    assert!(
        is_private_ip_addr(&IpAddr::V6(Ipv6Addr::LOCALHOST)),
        "IPv6 loopback ::1 must be vetoed as private"
    );
}

#[test]
fn resolved_ipv6_link_local_is_screened_as_private() {
    // fe80::/10 link-local — the IPv6 analog of the 169.254 rebind target.
    assert!(
        is_private_ip_addr(&IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
        "IPv6 link-local fe80::1 must be vetoed as private"
    );
}

#[test]
fn resolved_public_google_dns_is_not_screened() {
    // A legitimate public A record must pass the veto (no false refusal).
    assert!(
        !is_private_ip_addr(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        "public 8.8.8.8 must NOT be vetoed"
    );
}

#[test]
fn resolved_public_cloudflare_dns_is_not_screened() {
    assert!(
        !is_private_ip_addr(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        "public 1.1.1.1 must NOT be vetoed"
    );
}

// ==========================================================================
// Group B — driven `S3Source::chunks()` production path through
// `parse_http_endpoint`. The private-endpoint allowance is per-source Tier-A
// config (`HttpClientConfig.allow_private_endpoint`), threaded into each source
// by `TestApi.s3_source_with_endpoint_allow_private`, so each test sets exactly
// the state it needs with no process-global env and no serialization.
// ==========================================================================

/// Syntactically valid S3 bucket name so `validate_bucket_name` passes and
/// execution reaches the endpoint screen.
const BUCKET: &str = "keyhog-rebind-bucket";

/// Exact literal-host SSRF refusal reason for `source == "S3"`.
const SSRF_STRING_REFUSAL: &str =
    "refusing S3 endpoint: host is a private, loopback, link-local, or cloud-metadata address (SSRF)";

/// Collect all chunk rows produced for `endpoint` with the SSRF endpoint screen
/// either active (`allow_private = false`) or opted out (`true`) — the Tier-A
/// config (`HttpClientConfig.allow_private_endpoint`) replacement for the retired
/// `KEYHOG_ALLOW_PRIVATE_CLOUD_ENDPOINT` env, threaded per-source so no
/// process-global state is touched and the tests need no serialization.
fn rows_for(
    endpoint: &str,
    allow_private: bool,
) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>> {
    TestApi
        .s3_source_with_endpoint_allow_private(BUCKET, endpoint, allow_private)
        .chunks()
        .collect()
}

/// Drive the source for `endpoint` with the SSRF screen ACTIVE (no opt-in) and
/// return the single error string, asserting the source aborts with exactly one
/// error row.
fn single_refusal_no_optin(endpoint: &str) -> String {
    let rows = rows_for(endpoint, false);
    assert_eq!(
        rows.len(),
        1,
        "an SSRF-refused endpoint must abort with exactly one error row before listing; \
         got {} row(s) for {endpoint}",
        rows.len()
    );
    match rows.into_iter().next().expect("one row") {
        Ok(chunk) => panic!(
            "endpoint {endpoint} must be REFUSED, but a chunk was produced: {:?}",
            chunk.metadata
        ),
        Err(error) => error.to_string(),
    }
}

#[test]
fn literal_imds_metadata_endpoint_refused_by_string_screen() {
    // 169.254.169.254 is caught by the literal-host string screen (the resolve
    // step is never reached), so the message is the string-screen reason.
    let error = single_refusal_no_optin("http://169.254.169.254");
    assert!(
        error.contains(SSRF_STRING_REFUSAL),
        "IMDS literal must be refused with the string-screen SSRF reason, got: {error}"
    );
}

#[test]
fn literal_loopback_endpoint_refused_by_string_screen() {
    let error = single_refusal_no_optin("http://127.0.0.1:9000");
    assert!(
        error.contains(SSRF_STRING_REFUSAL),
        "127.0.0.1 literal must be refused with the string-screen SSRF reason, got: {error}"
    );
}

#[test]
fn literal_loopback_refusal_is_source_error_other_with_full_wrapper() {
    // Full operator-facing Display shape (SourceError::Other wraps the reason).
    let error = single_refusal_no_optin("http://127.0.0.1");
    assert_eq!(
        error,
        format!(
            "failed to read source: {SSRF_STRING_REFUSAL}. \
Fix: adjust the source settings or input so KeyHog can read plain text safely"
        ),
        "refusal must be a SourceError::Other with the exact wrapped message"
    );
}

#[test]
fn config_allow_private_allows_loopback_endpoint() {
    // With `allow_private_endpoint = true`, BOTH the string screen and the
    // resolve screen are disabled: 127.0.0.1 is accepted past
    // `parse_http_endpoint`, so the source proceeds to connect (to a dead port
    // -> connection error), and NO row is an SSRF refusal.
    let rows = rows_for("http://127.0.0.1:1", true);
    assert!(
        !rows.is_empty(),
        "an accepted-but-unreachable loopback endpoint must still yield a connection error row"
    );
    for row in &rows {
        if let Err(error) = row {
            let message = error.to_string();
            assert!(
                !message.contains("(SSRF)"),
                "the allow-private config must suppress the SSRF refusal, got: {message}"
            );
        }
    }
}

#[test]
fn config_screen_active_refuses_loopback_endpoint() {
    // With `allow_private_endpoint = false` (the default) the screen stays active
    // and 127.0.0.1 is refused with the string-screen reason — the config bool,
    // not a truthy/falsy env string, is now the single decision input.
    let rows = rows_for("http://127.0.0.1", false);
    assert_eq!(
        rows.len(),
        1,
        "screen-active config must refuse the endpoint"
    );
    let error = match rows.into_iter().next().expect("one row") {
        Ok(chunk) => panic!("must be refused, got chunk: {:?}", chunk.metadata),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains(SSRF_STRING_REFUSAL),
        "screen-active config must refuse loopback with the SSRF reason, got: {error}"
    );
}

#[test]
fn public_host_passes_both_screens_resolve_step_fails_open() {
    // `.invalid` (RFC 6761) is a public-classified domain that NXDOMAINs. It
    // passes the string screen, and the new resolve step FAILS OPEN on the
    // resolution error (no address -> no SSRF target), so `parse_http_endpoint`
    // returns Ok and any later failure is a network/DNS error — NOT an SSRF
    // refusal and NOT an invalid-endpoint rejection.
    let rows = rows_for("https://objectstore.public.invalid", false);
    for row in &rows {
        if let Err(error) = row {
            let message = error.to_string();
            assert!(
                !message.contains("(SSRF)"),
                "a public host must NOT be refused by the SSRF screen, got: {message}"
            );
            assert!(
                !message.contains("invalid S3 endpoint"),
                "a public host must NOT be refused as an invalid endpoint, got: {message}"
            );
        }
    }
}
