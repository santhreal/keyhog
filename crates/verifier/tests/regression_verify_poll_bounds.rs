//! Regression coverage for the verifier's capped body reads and the
//! retry-exhaust path.
//!
//! Two distinct capped-read surfaces live in the verifier:
//!
//!   * `verify::response::read_response_body`: the 1 MiB
//!     `MAX_RESPONSE_BODY_BYTES` cap on the HTTP verification response,
//!     reachable end to end through the `VerificationEngine`. A body over the
//!     cap must fail **loud** (`RESPONSE_TOO_LARGE_ERROR`), never silently
//!     truncate to a live/dead verdict off a partial body; a body **at** the
//!     cap (`==`, not `>`) must still be read whole; an under-cap body is read
//!     whole and evaluated.
//!   * `oob::client::read_capped_bytes` / `MAX_POLL_BODY_BYTES`: the same
//!     defensive shape on the interactsh `/poll` path.
//!
//! The retry loop's exhaustion contract is also pinned here: when every attempt
//! is transient the last attempt's result **and metadata** survive (they are
//! not dropped to a silent empty map), and a truly empty exhaustion emits the
//! loud `MAX_RETRIES_ERROR` rather than a silent success.
//!
//! Every assertion below is a concrete expected value, an exact error string,
//! an exact `VerificationResult` variant, an exact request count, or an exact
//! `(min, max)` delay-bound pair.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use keyhog_core::{
    AuthSpec, DedupedMatch, DetectorSpec, HttpMethod, MatchLocation, Severity, SuccessSpec,
    VerificationResult, VerifySpec,
};
use keyhog_verifier::testing::{
    TestApi, VerifierTestApi, BODY_NOT_UTF8_ERROR, BODY_READ_FAILED_ERROR, MAX_RETRIES_ERROR,
    RESPONSE_TOO_LARGE_ERROR,
};
use keyhog_verifier::{VerificationEngine, VerifyConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The verifier's HTTP response cap. Mirrors `MAX_RESPONSE_BODY_BYTES` in
/// `verify::response`. Kept as a literal here so a change to the production
/// constant surfaces as a failing boundary assertion, not a silent follow.
const RESPONSE_CAP: usize = 1024 * 1024;

/// Spawn a one-shot-per-connection HTTP/1.1 server that always replies with the
/// given status and raw body bytes, counting every request it serves. Returns
/// the base URL (`http://127.0.0.1:<port>`).
async fn body_server(status: u16, body: Vec<u8>, count: Arc<AtomicUsize>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let body = body.clone();
            let count = count.clone();
            tokio::spawn(async move {
                // Drain the (small) request headers so the client's write side
                // completes before we answer.
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                count.fetch_add(1, Ordering::SeqCst);
                let header = format!(
                    "HTTP/1.1 {status} TEST\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let mut out = header.into_bytes();
                out.extend_from_slice(&body);
                let _ = stream.write_all(&out).await;
                let _ = stream.flush().await;
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// Return a body shorter than its declared length so reqwest surfaces the
/// transport cause from the response stream.
async fn truncated_body_server(count: Arc<AtomicUsize>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let count = count.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                count.fetch_add(1, Ordering::SeqCst);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\nConnection: close\r\n\r\nshort",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn group_for(detector_id: &str) -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(detector_id),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: keyhog_core::SensitiveString::from("secret-value"),
        credential_hash: [0u8; 32].into(),
        primary_location: MatchLocation {
            source: Arc::from("fs"),
            file_path: Some(Arc::from("fixture.txt")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: vec![],
        companions: HashMap::new(),
        confidence: Some(1.0),
    }
}

fn engine_for(spec: DetectorSpec) -> VerificationEngine {
    VerificationEngine::new(
        &[spec],
        VerifyConfig {
            danger_allow_private_ips: true,
            danger_allow_http: true,
            ..Default::default()
        },
    )
    .unwrap()
}

/// Build a single-request detector that POSTs the given URL and (optionally)
/// requires a specific success status.
fn detector_for(id: &str, url: String, success: Option<SuccessSpec>) -> DetectorSpec {
    DetectorSpec {
        id: id.into(),
        name: id.into(),
        service: "test".into(),
        severity: Severity::Critical,
        keywords: vec![],
        patterns: vec![],
        companions: vec![],
        tests: vec![],
        min_confidence: None,
        verify: Some(VerifySpec {
            service: "test".into(),
            method: Some(HttpMethod::Post),
            url: Some(url),
            auth: Some(AuthSpec::None {}),
            headers: vec![],
            body: None,
            success,
            metadata: vec![],
            timeout_ms: None,
            steps: vec![],
            allowed_domains: vec!["127.0.0.1".into()],
            oob: None,
        }),
        ..Default::default()
    }
}

fn expect_error(v: &VerificationResult) -> &str {
    match v {
        VerificationResult::Error(m) => m.as_str(),
        other => panic!("expected VerificationResult::Error, got {other:?}"),
    }
}

async fn verify_once(detector: DetectorSpec, id: &str) -> keyhog_core::VerifiedFinding {
    engine_for(detector)
        .verify_all(vec![group_for(id)])
        .await
        .into_iter()
        .next()
        .expect("exactly one finding")
}

// ---------------------------------------------------------------------------
// HTTP response-cap bounds (read_response_body / MAX_RESPONSE_BODY_BYTES)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn over_cap_response_fails_loud_not_silent_verdict() {
    // Body is cap + 100 bytes: read_response_body must abort with the loud
    // "too large" error rather than parse a live/dead signal off a truncation.
    let count = Arc::new(AtomicUsize::new(0));
    let over = vec![b'A'; RESPONSE_CAP + 100];
    let base = body_server(200, over, count.clone()).await;
    let detector = detector_for("over-cap", format!("{base}/probe"), None);

    let finding = verify_once(detector, "over-cap").await;

    assert_eq!(
        expect_error(&finding.verification),
        RESPONSE_TOO_LARGE_ERROR,
        "an over-cap 200 body must surface the exact loud too-large error, not a verdict"
    );
    // The read aborts on the first over-cap chunk; the request is issued once
    // (the too-large error is non-transient, so no retry budget is spent).
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn exactly_cap_response_is_read_whole() {
    // Boundary: the guard is `>` cap, so a body of EXACTLY the cap is accepted
    // and read in full. With no success spec, is_live == (status == 200) and a
    // benign body yields Live, which is only reachable if the whole body was
    // read without tripping the cap.
    let count = Arc::new(AtomicUsize::new(0));
    let exact = vec![b'A'; RESPONSE_CAP];
    let base = body_server(200, exact, count.clone()).await;
    let detector = detector_for("exact-cap", format!("{base}/probe"), None);

    let finding = verify_once(detector, "exact-cap").await;

    assert_eq!(
        finding.verification,
        VerificationResult::Live,
        "a body of exactly the cap must be read whole (guard is strict `>` cap)"
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn one_over_cap_is_the_flip_point() {
    // Cap + 1 must already fail: proves the boundary is exact, not off-by-one
    // in the lenient direction.
    let count = Arc::new(AtomicUsize::new(0));
    let over = vec![b'A'; RESPONSE_CAP + 1];
    let base = body_server(200, over, count.clone()).await;
    let detector = detector_for("cap-plus-one", format!("{base}/probe"), None);

    let finding = verify_once(detector, "cap-plus-one").await;

    assert_eq!(
        expect_error(&finding.verification),
        RESPONSE_TOO_LARGE_ERROR
    );
}

#[tokio::test]
async fn under_cap_benign_body_is_live() {
    let count = Arc::new(AtomicUsize::new(0));
    let base = body_server(200, b"{\"status\":\"ok\"}".to_vec(), count.clone()).await;
    let detector = detector_for(
        "under-cap-live",
        format!("{base}/probe"),
        Some(SuccessSpec {
            status: Some(200),
            ..Default::default()
        }),
    );

    let finding = verify_once(detector, "under-cap-live").await;

    assert_eq!(finding.verification, VerificationResult::Live);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn under_cap_error_token_body_is_dead() {
    // 200 + populated JSON error key: is_live is true on status, but
    // body_indicates_error flips it to Dead. Proves the whole body reached the
    // error-token contract.
    let count = Arc::new(AtomicUsize::new(0));
    let base = body_server(
        200,
        b"{\"error\":\"invalid token\"}".to_vec(),
        count.clone(),
    )
    .await;
    let detector = detector_for("under-cap-dead", format!("{base}/probe"), None);

    let finding = verify_once(detector, "under-cap-dead").await;

    assert_eq!(finding.verification, VerificationResult::Dead);
}

#[tokio::test]
async fn non_utf8_body_preserves_the_utf8_cause() {
    // Under-cap but binary: the whole body is read, then UTF-8 decode fails
    // loud rather than silently dropping the body.
    let count = Arc::new(AtomicUsize::new(0));
    let base = body_server(200, vec![0xFF, 0xFE, 0x00, 0x80], count.clone()).await;
    let detector = detector_for("non-utf8", format!("{base}/probe"), None);

    let finding = verify_once(detector, "non-utf8").await;

    let error = expect_error(&finding.verification);
    assert!(
        error.starts_with(BODY_NOT_UTF8_ERROR),
        "the stable operator guidance must remain the error prefix: {error}"
    );
    assert!(
        error.contains("Cause: invalid utf-8 sequence") && error.contains("index 0"),
        "the concrete UTF-8 failure must survive: {error}"
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn truncated_body_preserves_redacted_transport_cause() {
    let count = Arc::new(AtomicUsize::new(0));
    let base = truncated_body_server(count.clone()).await;
    let detector = detector_for("truncated", format!("{base}/{{{{match}}}}"), None);

    let finding = verify_once(detector, "truncated").await;

    let error = expect_error(&finding.verification);
    assert!(
        error.starts_with(BODY_READ_FAILED_ERROR),
        "the stable operator guidance must remain the error prefix: {error}"
    );
    assert!(
        error.contains("Cause:") && error.len() > BODY_READ_FAILED_ERROR.len() + 8,
        "the concrete response-stream failure must survive: {error}"
    );
    assert!(
        !error.contains("secret-value"),
        "the request URL and credential must be stripped from the cause: {error}"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        3,
        "transient body reads must consume the three-attempt retry budget"
    );
}

// ---------------------------------------------------------------------------
// Retry-exhaust path (retry_loop / MAX_RETRIES / delay bounds)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn transient_500_exhausts_retry_budget_loud() {
    // A body-less 500 on every attempt: retryable + transient, so the loop
    // spends all three attempts and returns the loud RateLimited verdict (the
    // last transient attempt), never a silent Dead/empty result.
    let count = Arc::new(AtomicUsize::new(0));
    let base = body_server(503, b"upstream down".to_vec(), count.clone()).await;
    let detector = detector_for("retry-503", format!("{base}/probe"), None);

    let finding = verify_once(detector, "retry-503").await;

    assert_eq!(
        finding.verification,
        VerificationResult::RateLimited,
        "an all-503 verify must exhaust the budget to a loud transient verdict"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        3,
        "MAX_VERIFY_ATTEMPTS is 3; every transient attempt must be spent"
    );
}

#[tokio::test]
async fn retry_exhaustion_preserves_last_metadata_and_stays_loud() {
    // The extracted retry loop's exhaustion contract: when all attempts are
    // transient, the LAST attempt's result and metadata survive, they are not
    // dropped to an empty map (the historical silent-loss bug).
    let (result, metadata) = TestApi.retry_loop_preserves_metadata_on_exhaustion().await;

    match result {
        VerificationResult::Error(msg) => {
            assert_eq!(msg, "transient verifier failure");
        }
        other => panic!("expected the preserved transient Error, got {other:?}"),
    }
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata.get("oob_id").map(String::as_str), Some("abc"));
}

#[tokio::test]
async fn max_retries_error_is_loud_and_actionable() {
    // The truly-empty exhaustion sentinel must lead with the back-compat phrase
    // and carry an operator fix (never a silent empty/success).
    assert!(
        MAX_RETRIES_ERROR.starts_with("max retries exceeded"),
        "downstream .contains(\"max retries exceeded\") checks must keep matching"
    );
    assert!(MAX_RETRIES_ERROR.contains("Fix:"));
    assert!(MAX_RETRIES_ERROR.contains("rate-limit"));
}

#[tokio::test]
async fn retry_delay_bounds_zeroth_attempt_has_no_delay() {
    // Attempt 0 never sleeps regardless of base delay.
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(0, 100), (0, 0));
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(0, 500), (0, 0));
}

#[tokio::test]
async fn retry_delay_bounds_zero_base_disables_backoff() {
    // A zero base delay collapses the whole schedule to (0, 0) at any attempt.
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(1, 0), (0, 0));
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(5, 0), (0, 0));
}

#[tokio::test]
async fn retry_delay_bounds_are_exponential_with_quarter_jitter() {
    // base * 2^(attempt-1), jitter = base/4 (min 1) on top.
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(1, 100), (100, 125));
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(2, 100), (200, 250));
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(3, 100), (400, 500));
}

#[tokio::test]
async fn retry_delay_bounds_cap_the_exponent_at_ten() {
    // exponent = min(attempt - 1, 10): attempts 11 and 12 both saturate at
    // base * 2^10, preventing unbounded backoff growth.
    let at_eleven = TestApi.retry_delay_bounds_for_attempt(11, 100);
    let at_twelve = TestApi.retry_delay_bounds_for_attempt(12, 100);
    assert_eq!(at_eleven, (102_400, 128_000));
    assert_eq!(at_twelve, at_eleven, "the exponent is capped at 10");
}

// ---------------------------------------------------------------------------
// OOB poll client bounds (correlation id / mint shape)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oob_client_correlation_id_is_exact_len() {
    let client = TestApi
        .interactsh_client_for_test("https://example.test")
        .expect("test interactsh client must construct");
    let cid = TestApi.interactsh_client_correlation_id(&client);
    assert_eq!(cid, "abcdefghijklmnopqrstuvwx");
    assert_eq!(cid.len(), 24);
}

#[tokio::test]
async fn oob_minted_url_shape_is_bounded_and_prefixed() {
    let client = TestApi
        .interactsh_client_for_test("https://example.test")
        .expect("test interactsh client must construct");
    let cid = TestApi
        .interactsh_client_correlation_id(&client)
        .to_string();
    let minted = TestApi.interactsh_client_mint_url(&client);

    // unique_id = correlation_id(24) || per-finding suffix(24) = 48 chars.
    assert_eq!(minted.unique_id.len(), 48);
    assert!(minted.unique_id.starts_with(&cid));
    // Host is `<unique_id>.<server-host>`, url is the https form of the host.
    assert_eq!(minted.host, format!("{}.example.test", minted.unique_id));
    assert_eq!(minted.url, format!("https://{}", minted.host));
    // Suffix is DNS-safe (lowercase alnum), never leaking padding/scheme chars.
    let suffix = &minted.unique_id[24..];
    assert!(suffix
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
}

#[tokio::test]
async fn body_indicates_error_contract_is_value_gated() {
    // The response-body error contract that gates Live->Dead: only a *populated*
    // error key counts; benign JSON shapes and embedded substrings do not.
    assert!(TestApi.body_indicates_error_for_test("{\"error\":\"boom\"}"));
    assert!(!TestApi.body_indicates_error_for_test("{\"error\":null}"));
    assert!(!TestApi.body_indicates_error_for_test("{\"errors\":[]}"));
    assert!(!TestApi.body_indicates_error_for_test("{\"error_rate\":5}"));
    // Non-JSON: whole-word match, so an embedded token does not trip it.
    assert!(!TestApi.body_indicates_error_for_test("myinvalidatedname"));
    assert!(TestApi.body_indicates_error_for_test("request error occurred"));
}
