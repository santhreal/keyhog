//! Regression lock for the verifier's HTTP-status → `VerificationResult` verdict
//! map. The AWS STS live-probe classifier (`classify_aws_sts_failure`, in
//! `verifier/src/verify/aws.rs`) is the concrete, pure, network-free status
//! matrix that turns a provider response code into the verdict the operator
//! sees, and the `SuccessSpec` status gate (`evaluate_success`) is the pure
//! precursor that decides whether a 2xx is `Live` at all. A silent drift in
//! either, e.g. treating a 401 as `Dead` (a false "invalid" verdict) or a 403
//! as retryable (a live credential wrongly reported `RateLimited`), is a
//! correctness bug that ships silently, so every code in the matrix is pinned to
//! its exact `VerificationResult` variant AND its exact transient/retryable bool.
//!
//! The keyhog verdict vocabulary is `Live | Revoked | Dead | RateLimited |
//! Error(String) | Unverifiable | Skipped`; the task's generic
//! "Verified/Invalid/Unverified/Unknown" labels map onto it as:
//!   * 200  → `Live`            (verified; decided upstream, see the 200-boundary test)
//!   * 403  → `Dead`            (invalid credential: AWS returns 403, not 401, for bad creds)
//!   * 403 + clock skew → `Error` (transient; fix host clock and retry)
//!   * 429/500/503/redirect/other → `RateLimited` (transient/unknown → retry)
//!
//! Distinct from the iter8 probe-timeout mapping: this pins the *response-status*
//! matrix, not the request-error/timeout taxonomy.

use keyhog_core::{SuccessSpec, VerificationResult};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

/// Drive the real pure AWS STS status classifier.
fn classify(status: u16, body: &str) -> (VerificationResult, bool) {
    TestApi.classify_aws_sts_failure(status, body)
}

/// A representative non-skew STS 403 error body (invalid token).
const INVALID_TOKEN_BODY: &str = "<Error><Code>InvalidClientTokenId</Code></Error>";

// ── 403: the terminal "invalid credential" verdict ───────────────────────────

#[test]
fn status_403_invalid_credential_maps_to_dead_and_conclusive() {
    let (result, transient) = classify(403, INVALID_TOKEN_BODY);
    assert_eq!(result, VerificationResult::Dead);
    // Dead is a conclusive verdict: the retry loop must NOT re-probe it.
    assert!(
        !transient,
        "an ordinary STS 403 is conclusive, not retryable"
    );
}

#[test]
fn status_403_clock_skew_maps_to_transient_error_with_fix_guidance() {
    let body = "<ErrorResponse><Error><Code>RequestTimeTooSkewed</Code>\
                <Message>The difference between the request time and the current time is too large.</Message>\
                </Error></ErrorResponse>";
    let (result, transient) = classify(403, body);
    // Clock skew is a host-side problem, not a dead credential → retryable.
    assert!(transient, "clock skew is retryable after fixing host time");
    match result {
        VerificationResult::Error(message) => {
            assert!(
                message.contains("system time") && message.contains("retry"),
                "clock-skew verdict must tell the operator what to fix: {message}"
            );
        }
        other => panic!("RequestTimeTooSkewed must classify as Error, got {other:?}"),
    }
}

#[test]
fn status_403_skew_marker_match_is_exact_case_sensitive() {
    // Adversarial: the marker is matched with a case-SENSITIVE `contains`, so a
    // lowercased look-alike must fall through to the plain-403 `Dead` verdict,
    // never the transient clock-skew `Error`. A case-insensitive drift here
    // would keep re-probing a genuinely dead credential forever.
    let (result, transient) = classify(403, "<Error><Code>requesttimetooskewed</Code></Error>");
    assert_eq!(result, VerificationResult::Dead);
    assert!(!transient);
}

#[test]
fn status_403_skew_marker_matches_anywhere_in_body() {
    // The marker is recognized as a substring at any offset, not only as a
    // whole element (a real STS body wraps it in nested XML).
    let body = "prefix noise <Error><Code>RequestTimeTooSkewed</Code></Error> trailing";
    let (result, transient) = classify(403, body);
    assert!(transient);
    assert!(
        matches!(result, VerificationResult::Error(_)),
        "embedded skew marker must still produce the transient Error verdict"
    );
}

// ── 401: NOT dead: AWS uses 403 for bad creds, so 401 is an unexpected/retry ─

#[test]
fn status_401_unauthorized_maps_to_ratelimited_not_dead() {
    // Negative twin of the 403 case. STS returns 403 (not 401) for an invalid
    // credential, so a 401 is unexpected and is treated as transient/retryable,
    // NOT as a conclusive `Dead`. Locking this prevents a future "401 == invalid"
    // shortcut that would falsely bury a still-live credential.
    let (result, transient) = classify(401, "Unauthorized");
    assert_eq!(result, VerificationResult::RateLimited);
    assert!(transient, "an unexpected 401 must remain retryable");
}

// ── 429: the exact rate-limit variant ────────────────────────────────────────

#[test]
fn status_429_too_many_requests_maps_to_ratelimited_transient() {
    let (result, transient) = classify(429, "Throttling: rate exceeded");
    assert_eq!(result, VerificationResult::RateLimited);
    assert!(transient, "429 is always retryable");
}

// ── 5xx: server-side / unknown → retryable RateLimited ───────────────────────

#[test]
fn status_500_server_error_maps_to_ratelimited_transient() {
    let (result, transient) = classify(500, "Internal Server Error");
    assert_eq!(result, VerificationResult::RateLimited);
    assert!(transient);
}

#[test]
fn status_503_service_unavailable_maps_to_ratelimited_transient() {
    let (result, transient) = classify(503, "Service Unavailable");
    assert_eq!(result, VerificationResult::RateLimited);
    assert!(transient);
}

// ── redirects: not a success, not conclusive → retryable ─────────────────────

#[test]
fn redirect_301_and_302_map_to_ratelimited_transient() {
    for status in [301u16, 302u16] {
        let (result, transient) = classify(status, "");
        assert_eq!(
            result,
            VerificationResult::RateLimited,
            "redirect status {status} must not be a conclusive verdict"
        );
        assert!(transient, "redirect status {status} must be retryable");
    }
}

// ── 400: boundary, unexpected 4xx defaults to retryable, never Dead ─────────

#[test]
fn status_400_bad_request_defaults_to_ratelimited_transient() {
    // Only 403 is treated as the conclusive Dead verdict; every other 4xx
    // (including 400) defaults to the transient RateLimited branch. This pins
    // the "positive allowlist" shape of the matrix (403 is the sole terminal
    // failure code).
    let (result, transient) = classify(400, "MalformedQueryString");
    assert_eq!(result, VerificationResult::RateLimited);
    assert!(transient);
}

// ── 200 boundary: the classifier only handles FAILURES ───────────────────────

#[test]
fn status_200_is_not_the_classifiers_job_and_never_yields_a_failure_dead() {
    // The Live decision for a 200 is made upstream (in `build_sigv4_request`,
    // which parses identity metadata); the failure classifier is only reached
    // for non-200 responses. Calling it with 200 must therefore NOT invent a
    // `Dead`/conclusive verdict, it falls into the transient default. This
    // documents the invariant that a 200 is never routed through `classify`.
    let (result, transient) = classify(200, "irrelevant");
    assert_eq!(result, VerificationResult::RateLimited);
    assert!(transient);
    assert_ne!(
        result,
        VerificationResult::Dead,
        "a 200 must never be classified as a dead credential"
    );
}

// ── verdict → cache policy: the status→verdict chain feeds the verdict cache ──

#[test]
fn dead_and_live_verdicts_are_cacheable_transient_verdicts_are_not() {
    // The whole point of mapping a status to a *conclusive* verdict (Dead/Live)
    // vs a *transient* one (RateLimited/Error) is that only the conclusive ones
    // may be cached; a transient blip must be re-verified next scan rather than
    // pinning a misclassification for the cache TTL. Pin the full allowlist.
    let cacheable = |r: &VerificationResult| TestApi.verification_result_is_cacheable_for_test(r);

    assert!(cacheable(&VerificationResult::Live), "Live is conclusive");
    assert!(cacheable(&VerificationResult::Dead), "Dead is conclusive");
    assert!(cacheable(&VerificationResult::Revoked));
    assert!(cacheable(&VerificationResult::Unverifiable));
    assert!(cacheable(&VerificationResult::Skipped));

    assert!(
        !cacheable(&VerificationResult::RateLimited),
        "a 429/5xx/redirect RateLimited verdict must be re-verified, never cached"
    );
    assert!(
        !cacheable(&VerificationResult::Error("clock skew".into())),
        "a transient Error verdict must be re-verified, never cached"
    );
}

// ── SuccessSpec status gate: the pure 200/redirect/429 success precursor ──────

#[test]
fn success_status_gate_accepts_exactly_200_and_rejects_redirect_and_429() {
    // The generic (non-AWS) verdict path treats a response as `Live` only when
    // the detector's success status matches. With `status = 200`, a 200 is the
    // sole success; a 201, a 302 redirect, and a 429 are all NOT success and
    // therefore never `Live`.
    let spec = SuccessSpec {
        status: Some(200),
        ..Default::default()
    };
    assert!(TestApi.evaluate_success_for_test(&spec, 200, ""));
    assert!(!TestApi.evaluate_success_for_test(&spec, 201, ""));
    assert!(
        !TestApi.evaluate_success_for_test(&spec, 302, ""),
        "a redirect is not a success"
    );
    assert!(
        !TestApi.evaluate_success_for_test(&spec, 429, ""),
        "a rate-limit status is not a success"
    );
}

#[test]
fn success_status_not_excludes_only_the_named_code() {
    // `status_not = 429` rejects exactly a 429 and leaves every other status
    // (including 200 and 403) passing the status gate, the negative twin of the
    // positive `status` gate.
    let spec = SuccessSpec {
        status_not: Some(429),
        ..Default::default()
    };
    assert!(!TestApi.evaluate_success_for_test(&spec, 429, ""));
    assert!(TestApi.evaluate_success_for_test(&spec, 200, ""));
    assert!(TestApi.evaluate_success_for_test(&spec, 403, ""));
}
