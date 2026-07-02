//! Regression coverage for the WebSource SSRF surface (host screen + redirect
//! revalidation) and the HAR 1.2 expansion parser.
//!
//! Two invariants are locked here:
//!
//! 1. Every SSRF host decision on the web fetch path delegates to the single
//!    canonical predicate `keyhog_verifier::ssrf::is_private_url` — WebSource
//!    must NOT carry a hand-rolled fork. The classification matrix asserts the
//!    exact bool the canonical returns AND that `is_disallowed_web_host` agrees
//!    with it for every case, so a re-forked copy that drifts fails here.
//! 2. A redirect whose target resolves to a private / loopback / link-local /
//!    metadata address is refused mid-chain (DNS-rebinding / open-redirect SSRF
//!    pivot), while a redirect to an allowed host is followed to completion.
//!
//! The HAR half asserts exact chunk counts, exact `source_type` + `path`
//! metadata, and the exact embedded secret bytes (including base64-decoded
//! response bodies) the parser must surface.

#![cfg(feature = "web")]

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};

fn loopback_source(url: String) -> keyhog_sources::WebSource {
    TestApi.web_source_with_autoroute_loopback_calibration(vec![url], true)
}

// ----------------------------------------------------------------------------
// SSRF host / IP classification — canonical predicate reuse (no hand-rolled fork)
// ----------------------------------------------------------------------------

#[test]
fn is_private_url_classifies_ssrf_targets_with_exact_bools() {
    use keyhog_verifier::ssrf::is_private_url;

    // Positive: private / loopback / link-local / metadata / integer-encoded /
    // internal-suffix hosts must all classify as private (blocked).
    assert_eq!(is_private_url("http://127.0.0.1/"), true, "loopback IPv4");
    assert_eq!(
        is_private_url("http://169.254.169.254/latest/meta-data/iam/"),
        true,
        "AWS metadata link-local"
    );
    assert_eq!(is_private_url("http://10.0.0.5/"), true, "RFC1918 10/8");
    assert_eq!(
        is_private_url("http://192.168.1.1/admin"),
        true,
        "RFC1918 192.168/16"
    );
    assert_eq!(
        is_private_url("http://2130706433/"),
        true,
        "decimal-encoded 127.0.0.1"
    );
    assert_eq!(
        is_private_url("http://0x7f000001/"),
        true,
        "hex-encoded 127.0.0.1"
    );
    assert_eq!(is_private_url("http://localhost/"), true, "localhost");
    assert_eq!(
        is_private_url("http://metadata.google.internal/computeMetadata/"),
        true,
        ".internal suffix"
    );
    // Fail-CLOSED: non-http(s) scheme and unparseable string are blocked.
    assert_eq!(
        is_private_url("ftp://example.com/x"),
        true,
        "non-http scheme fails closed"
    );
    assert_eq!(
        is_private_url("::::not a url"),
        true,
        "unparseable URL fails closed"
    );

    // Negative twin: public routable hosts must classify as NOT private.
    assert_eq!(
        is_private_url("https://example.com/app.js"),
        false,
        "public domain"
    );
    assert_eq!(is_private_url("http://8.8.8.8/"), false, "public IPv4");
    assert_eq!(
        is_private_url("https://api.github.com/repos"),
        false,
        "public API host"
    );
}

#[test]
fn web_host_screen_matches_canonical_is_private_url_for_every_case() {
    use keyhog_verifier::ssrf::is_private_url;

    // The WebSource pre-filter (`is_disallowed_web_host`) MUST be the canonical
    // predicate, not a subset fork. Assert byte-for-byte agreement on the exact
    // adversarial cases a fork historically let slip (CGN, hex/decimal ints).
    let cases = [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://100.64.0.1/", // carrier-grade NAT — the classic fork gap
        "http://0x7f000001/",
        "http://2130706433/",
        "http://localhost/",
        "http://metadata.google.internal/",
        "https://example.com/app.js",
        "http://8.8.8.8/",
        "ftp://example.com/x",
    ];
    for url in cases {
        assert_eq!(
            TestApi.is_disallowed_web_host(url),
            is_private_url(url),
            "is_disallowed_web_host must delegate to the canonical is_private_url for {url}"
        );
    }

    // Concrete anchors so this test also fails if BOTH drift together.
    assert_eq!(TestApi.is_disallowed_web_host("http://100.64.0.1/"), true);
    assert_eq!(
        TestApi.is_disallowed_web_host("https://example.com/app.js"),
        false
    );
}

#[test]
fn is_disallowed_ip_screens_resolved_addresses_with_exact_bools() {
    use std::net::IpAddr;

    // Post-DNS resolution screen (rebinding defense) — assert the exact verdict
    // for each resolved address class.
    assert_eq!(
        TestApi.is_disallowed_ip("127.0.0.1".parse::<IpAddr>().unwrap()),
        true
    );
    assert_eq!(
        TestApi.is_disallowed_ip("169.254.169.254".parse::<IpAddr>().unwrap()),
        true
    );
    assert_eq!(
        TestApi.is_disallowed_ip("10.1.2.3".parse::<IpAddr>().unwrap()),
        true
    );
    assert_eq!(
        TestApi.is_disallowed_ip("::1".parse::<IpAddr>().unwrap()),
        true,
        "IPv6 loopback"
    );
    assert_eq!(
        TestApi.is_disallowed_ip("100.64.0.1".parse::<IpAddr>().unwrap()),
        true,
        "carrier-grade NAT"
    );
    // Negative twin: public routable addresses pass the screen.
    assert_eq!(
        TestApi.is_disallowed_ip("8.8.8.8".parse::<IpAddr>().unwrap()),
        false
    );
    assert_eq!(
        TestApi.is_disallowed_ip("1.1.1.1".parse::<IpAddr>().unwrap()),
        false
    );
}

// ----------------------------------------------------------------------------
// Redirect revalidation — e2e through the real WebSource fetch path
// ----------------------------------------------------------------------------

fn only_error_message(
    results: Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>>,
) -> String {
    assert_eq!(
        results.len(),
        1,
        "expected exactly one refusal row, got {results:?}"
    );
    match &results[0] {
        Ok(chunk) => panic!("expected a refusal error, got Ok chunk {chunk:?}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn redirect_to_metadata_host_is_refused_mid_chain() {
    let server = httpmock::MockServer::start();
    let _redirect = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/open-redirect");
        then.status(302).header(
            "location",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        );
    });

    let results: Vec<_> = loopback_source(server.url("/open-redirect"))
        .chunks()
        .collect();
    let message = only_error_message(results);
    assert!(
        message.contains("refusing to follow redirect"),
        "must name the refused redirect, got {message}"
    );
    assert!(
        message.contains("private / loopback / link-local / metadata-service"),
        "must name the SSRF class that triggered the refusal, got {message}"
    );
}

#[test]
fn redirect_to_allowed_host_is_followed_to_the_secret() {
    let server = httpmock::MockServer::start();
    let _start = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/start");
        // Relative Location resolves back to the (allowed) loopback server.
        then.status(302).header("location", "/final");
    });
    let _final = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/final");
        then.status(200)
            .header("content-type", "application/javascript")
            .body("const k = 'redirect_followed_secret_5150';\n");
    });

    let chunks: Vec<_> = loopback_source(server.url("/start"))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("redirect to an allowed host must be followed and scanned");

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].metadata.source_type, "web:js");
    assert!(
        chunks[0]
            .data
            .as_ref()
            .contains("redirect_followed_secret_5150"),
        "followed-redirect body must be scanned, got {:?}",
        chunks[0].data
    );
}

#[test]
fn redirect_loop_is_capped_at_the_redirect_limit() {
    let server = httpmock::MockServer::start();
    let _loop = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/loop");
        then.status(302).header("location", "/loop");
    });

    let results: Vec<_> = loopback_source(server.url("/loop")).chunks().collect();
    let message = only_error_message(results);
    assert!(
        message.contains("too many redirects (> 5)"),
        "redirect cap error must name the limit 5, got {message}"
    );
}

#[test]
fn redirect_to_non_http_scheme_is_refused() {
    let server = httpmock::MockServer::start();
    let _redirect = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/to-ftp");
        then.status(302)
            .header("location", "ftp://example.com/secret");
    });

    let results: Vec<_> = loopback_source(server.url("/to-ftp")).chunks().collect();
    let message = only_error_message(results);
    assert!(
        message.contains("unsupported URL scheme"),
        "non-http redirect scheme must be refused by name, got {message}"
    );
    assert!(
        message.contains("\"ftp\""),
        "refusal must quote the offending scheme, got {message}"
    );
}

// ----------------------------------------------------------------------------
// HAR 1.2 expansion — exact chunk count, metadata, and embedded secrets
// ----------------------------------------------------------------------------

const TWO_ENTRY_HAR: &str = r#"{
  "log": {
    "version": "1.2",
    "creator": {"name": "keyhog-test", "version": "1"},
    "entries": [
      {
        "request": {
          "method": "GET",
          "url": "https://api.example.test/login",
          "headers": [
            {"name": "Authorization", "value": "Bearer req_secret_AKIA_marker_001"}
          ]
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "headers": [],
          "content": {
            "mimeType": "application/json",
            "encoding": "base64",
            "text": "c2tfbGl2ZV9oYXJfcmVzcG9uc2Vfc2VjcmV0XzQy"
          }
        }
      },
      {
        "request": {
          "method": "POST",
          "url": "https://api.example.test/token",
          "headers": [],
          "postData": {
            "mimeType": "application/x-www-form-urlencoded",
            "text": "grant=refresh&token=post_body_secret_xyz789"
          }
        },
        "response": {
          "status": 401,
          "statusText": "Unauthorized",
          "headers": [],
          "content": {
            "mimeType": "text/plain",
            "text": "plain_response_marker"
          }
        }
      }
    ]
  }
}"#;

#[test]
fn har_two_entries_expand_to_four_chunks_with_exact_metadata() {
    let expanded = TestApi
        .expand_har(TWO_ENTRY_HAR.as_bytes(), "captured.har", 1_000_000)
        .expect("valid HAR must expand to Some(chunks)");
    let chunks: Vec<_> = expanded
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("no HAR entry should error under a 1MB cap");

    // Two entries × (request + response) = exactly four chunks, in order.
    assert_eq!(chunks.len(), 4, "chunks: {chunks:?}");

    assert_eq!(chunks[0].metadata.source_type, "wire:har:request");
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("captured.har#https://api.example.test/login")
    );
    assert!(chunks[0]
        .data
        .as_ref()
        .starts_with("GET https://api.example.test/login"));

    assert_eq!(chunks[1].metadata.source_type, "wire:har:response");
    assert_eq!(
        chunks[1].metadata.path.as_deref(),
        Some("captured.har#https://api.example.test/login")
    );
    assert!(chunks[1].data.as_ref().starts_with("200 OK"));

    assert_eq!(chunks[2].metadata.source_type, "wire:har:request");
    assert_eq!(
        chunks[2].metadata.path.as_deref(),
        Some("captured.har#https://api.example.test/token")
    );

    assert_eq!(chunks[3].metadata.source_type, "wire:har:response");
    assert!(chunks[3].data.as_ref().starts_with("401 Unauthorized"));
}

#[test]
fn har_surfaces_request_header_and_post_body_secrets_verbatim() {
    let expanded = TestApi
        .expand_har(TWO_ENTRY_HAR.as_bytes(), "captured.har", 1_000_000)
        .expect("valid HAR must expand");
    let chunks: Vec<_> = expanded
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("no entry error");

    // Outbound request Authorization header secret (entry 1 request).
    assert!(
        chunks[0]
            .data
            .as_ref()
            .contains("Authorization: Bearer req_secret_AKIA_marker_001"),
        "request chunk must carry the Authorization header verbatim, got {:?}",
        chunks[0].data
    );
    // Outbound POST body secret (entry 2 request).
    assert!(
        chunks[2].data.as_ref().contains("post_body_secret_xyz789"),
        "request chunk must carry the POST body verbatim, got {:?}",
        chunks[2].data
    );
}

#[test]
fn har_base64_response_body_is_decoded_before_scanning() {
    let expanded = TestApi
        .expand_har(TWO_ENTRY_HAR.as_bytes(), "captured.har", 1_000_000)
        .expect("valid HAR must expand");
    let chunks: Vec<_> = expanded
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("no entry error");

    // c2tfbGl2ZV9oYXJfcmVzcG9uc2Vfc2VjcmV0XzQy -> "sk_live_har_response_secret_42".
    assert!(
        chunks[1]
            .data
            .as_ref()
            .contains("sk_live_har_response_secret_42"),
        "base64 response body must be decoded, not left opaque; got {:?}",
        chunks[1].data
    );
    // The opaque base64 blob itself must NOT be what we scan.
    assert!(
        !chunks[1]
            .data
            .as_ref()
            .contains("c2tfbGl2ZV9oYXJfcmVzcG9uc2Vfc2VjcmV0XzQy"),
        "the raw base64 must be replaced by its decoded form, got {:?}",
        chunks[1].data
    );
}

#[test]
fn har_malformed_base64_response_falls_back_to_raw_text() {
    // encoding="base64" but the text is not valid base64: the parser must scan
    // the raw text rather than drop a credential-bearing body.
    let har = r#"{
      "log": {
        "version": "1.2",
        "entries": [
          {
            "request": {"method": "GET", "url": "https://x.example.test/a", "headers": []},
            "response": {
              "status": 200,
              "statusText": "OK",
              "headers": [],
              "content": {
                "mimeType": "application/json",
                "encoding": "base64",
                "text": "@@@not-base64@@@ secret_RAW_KEEP_777"
              }
            }
          }
        ]
      }
    }"#;

    let expanded = TestApi
        .expand_har(har.as_bytes(), "bad.har", 1_000_000)
        .expect("HAR shape must expand even with a bad base64 body");
    let chunks: Vec<_> = expanded
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("no entry error");

    assert_eq!(chunks.len(), 2, "one request + one response chunk");
    assert_eq!(chunks[1].metadata.source_type, "wire:har:response");
    assert!(
        chunks[1].data.as_ref().contains("secret_RAW_KEEP_777"),
        "malformed-base64 body must be scanned raw, got {:?}",
        chunks[1].data
    );
}

#[test]
fn compact_base64_text_strips_all_ascii_whitespace() {
    // Multi-line HAR base64 (Firefox wraps at 76 cols) must be joined before
    // decode. Exact string equality on both the whitespace and no-op paths.
    assert_eq!(
        TestApi.compact_har_base64_text("aW5ib3Vu\n  ZF9iZWFy\tVE9LRU4="),
        "aW5ib3VuZF9iZWFyVE9LRU4="
    );
    // No whitespace -> returned unchanged, byte-for-byte.
    assert_eq!(
        TestApi.compact_har_base64_text("aW5ib3VuZF9iZWFyVE9LRU4="),
        "aW5ib3VuZF9iZWFyVE9LRU4="
    );
    assert_eq!(TestApi.compact_har_base64_text(""), "");
}

#[test]
fn har_expansion_aborts_when_bodies_exceed_the_four_x_budget() {
    // budget = max_size * 4. With max_size = 10, budget = 40 bytes. A single
    // request rendered longer than 40 bytes must abort with a visible,
    // budget-naming truncation error rather than silently scanning partial.
    let long_url = format!("https://api.example.test/{}", "a".repeat(80));
    let har = format!(
        r#"{{"log":{{"entries":[{{"request":{{"method":"GET","url":"{long_url}","headers":[]}},"response":{{"status":200,"headers":[]}}}}]}}}}"#
    );

    let expanded = TestApi
        .expand_har(har.as_bytes(), "big.har", 10)
        .expect("HAR shape still expands; budget abort is per-entry");
    // The single row is the truncation error (request already blew the budget).
    assert_eq!(expanded.len(), 1, "rows: {expanded:?}");
    let message = match &expanded[0] {
        Ok(chunk) => panic!("expected truncation error, got chunk {chunk:?}"),
        Err(error) => error.to_string(),
    };
    assert!(
        message.contains("HAR source scan was truncated"),
        "truncation must be operator-visible, got {message}"
    );
    assert!(
        message.contains("40-byte expansion budget"),
        "truncation must name the exact 40-byte budget (10 * 4), got {message}"
    );
}

#[test]
fn non_har_json_returns_none_but_har_shaped_input_expands() {
    // Plain JSON without the log/entries markers is NOT a HAR: the parser must
    // return None so the caller falls back to raw text scanning.
    assert!(
        TestApi
            .expand_har(br#"{"token":"not_a_har_marker"}"#, "plain.json", 1_000_000)
            .is_none(),
        "non-HAR JSON must return None (raw-text fallback)"
    );

    // A minimal single-entry HAR expands to exactly 2 chunks.
    let minimal = r#"{"log":{"entries":[{"request":{"method":"GET","url":"https://h.example.test/","headers":[]},"response":{"status":204,"headers":[]}}]}}"#;
    let expanded = TestApi
        .expand_har(minimal.as_bytes(), "min.har", 1_000_000)
        .expect("minimal HAR must expand to Some");
    let chunks: Vec<_> = expanded
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("no entry error");
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].metadata.source_type, "wire:har:request");
    assert_eq!(chunks[1].metadata.source_type, "wire:har:response");
    assert!(chunks[1].data.as_ref().starts_with("204"));
}
