//! Regression lock: verifier live-probe **status/error -> verdict** mapping contract.
//!
//! The live-probe path in `crates/verifier/src/verify/` funnels every HTTP
//! outcome into exactly one [`keyhog_core::VerificationResult`] variant, and
//! then a transport failure (timeout / connect / redirect / other) is folded
//! into the `Error(String)` variant carrying one of a small, fixed set of
//! operator-facing reason strings. Two contracts must never silently drift:
//!
//!   1. The **verdict wire contract**: the snake_case serde tag each verdict
//!      serializes to. Reporters, the SARIF writer, and the JSON output all key
//!      off these exact tags, so a rename here is a breaking, silent data bug.
//!      A live 200 probe -> `Live` -> `"live"`; a 401/403 rejection -> `Dead`
//!      -> `"dead"`; a 429/5xx -> `RateLimited` -> `"rate_limited"`; a timeout
//!      or network error -> `Error(msg)` -> `{"error": msg}`.
//!
//!   2. The **transport-error reason contract**: the exact `Error(...)` payload
//!      strings for the timeout / connect / redirect / request-failed paths, the
//!      three response-body errors, and the `blocked:` refusal family. Each
//!      actionable failure leads with its legacy short phrase (Law 3 substring
//!      compatibility) and carries a `Fix:`; each refusal is `blocked:`-prefixed
//!      and deliberately carries NO `Fix:`. They must all stay pairwise distinct
//!      so an operator can tell a timeout from a dropped connection.
//!
//! These are the pure, network-free halves of the mapping. Nothing here opens a
//! socket; every assertion is a concrete expected value.

use std::collections::HashSet;
use std::time::Duration;

use keyhog_core::VerificationResult;
use keyhog_verifier::oob::InteractshError;
use keyhog_verifier::testing::{
    invalid_url_error, redact_interactsh_error, BODY_NOT_UTF8_ERROR, BODY_READ_FAILED_ERROR,
    CONNECTION_FAILED_ERROR, DNS_NO_ADDRESSES_ERROR, HTTPS_ONLY_ERROR, PRIVATE_URL_ERROR,
    REDIRECT_LIMIT_ERROR, REQUEST_FAILED_ERROR, RESPONSE_TOO_LARGE_ERROR, TIMEOUT_ERROR,
};

// ────────────────────────────────────────────────────────────────────────────
// Group A (verdict wire contract (the output side of status -> verdict)).
// A downstream JSON/SARIF consumer keys off these exact snake_case tags.
// ────────────────────────────────────────────────────────────────────────────

/// A live 200 probe maps to `Live`, whose wire tag is the bare string `"live"`.
#[test]
fn live_verdict_serializes_to_snake_case_live() {
    let json = serde_json::to_string(&VerificationResult::Live).expect("serialize Live");
    assert_eq!(json, "\"live\"");
}

/// A 401/403 rejection maps to `Dead`, whose wire tag is `"dead"`.
#[test]
fn dead_verdict_serializes_to_snake_case_dead() {
    let json = serde_json::to_string(&VerificationResult::Dead).expect("serialize Dead");
    assert_eq!(json, "\"dead\"");
}

/// A 429 / retryable 5xx maps to `RateLimited`; the multi-word variant must
/// serialize as `rate_limited` (snake_case), never `rateLimited`/`RateLimited`.
#[test]
fn rate_limited_verdict_serializes_snake_case() {
    let json =
        serde_json::to_string(&VerificationResult::RateLimited).expect("serialize RateLimited");
    assert_eq!(json, "\"rate_limited\"");
}

/// A timeout / network failure maps to the `Error(String)` variant, which
/// serializes as an externally-tagged object `{"error": <reason>}` carrying the
/// exact reason string verbatim (here the canonical timeout reason).
#[test]
fn timeout_maps_to_error_variant_with_exact_payload_under_error_tag() {
    let verdict = VerificationResult::Error(TIMEOUT_ERROR.to_string());
    let json = serde_json::to_string(&verdict).expect("serialize Error");
    let value: serde_json::Value = serde_json::from_str(&json).expect("reparse Error json");

    let obj = value
        .as_object()
        .expect("Error serializes to a JSON object");
    assert_eq!(obj.len(), 1, "Error object has exactly one key");
    let payload = obj
        .get("error")
        .and_then(|v| v.as_str())
        .expect("object is keyed by `error` with a string payload");
    assert_eq!(payload, TIMEOUT_ERROR);
}

/// The full seven-variant verdict enum: every variant serializes to a distinct
/// tag, and the four unit verdicts carry exactly the expected snake_case names.
#[test]
fn all_seven_verdict_tags_are_distinct_and_named() {
    let variants = [
        VerificationResult::Live,
        VerificationResult::Revoked,
        VerificationResult::Dead,
        VerificationResult::RateLimited,
        VerificationResult::Error("boom".to_string()),
        VerificationResult::Unverifiable,
        VerificationResult::Skipped,
    ];
    let tags: Vec<String> = variants
        .iter()
        .map(|v| serde_json::to_string(v).expect("serialize verdict"))
        .collect();

    assert_eq!(tags[0], "\"live\"");
    assert_eq!(tags[1], "\"revoked\"");
    assert_eq!(tags[2], "\"dead\"");
    assert_eq!(tags[3], "\"rate_limited\"");
    assert_eq!(tags[4], "{\"error\":\"boom\"}");
    assert_eq!(tags[5], "\"unverifiable\"");
    assert_eq!(tags[6], "\"skipped\"");

    let unique: HashSet<&String> = tags.iter().collect();
    assert_eq!(unique.len(), 7, "all seven verdict tags must be distinct");
}

/// The `Error` verdict round-trips: deserializing its serialized form yields an
/// equal value with the reason string byte-for-byte preserved (no truncation of
/// the multi-line connection-failure reason).
#[test]
fn error_verdict_roundtrips_and_preserves_exact_reason() {
    let original = VerificationResult::Error(CONNECTION_FAILED_ERROR.to_string());
    let json = serde_json::to_string(&original).expect("serialize");
    let restored: VerificationResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored, original);
    match restored {
        VerificationResult::Error(reason) => assert_eq!(reason, CONNECTION_FAILED_ERROR),
        other => panic!("expected Error variant, got {other:?}"),
    }
}

/// Deserialization of the snake_case tags recovers the exact unit verdicts
/// the input side of the wire contract, exercised as a negative twin to the
/// serialize tests above.
#[test]
fn snake_case_tags_deserialize_to_expected_unit_verdicts() {
    let live: VerificationResult = serde_json::from_str("\"live\"").expect("live");
    let dead: VerificationResult = serde_json::from_str("\"dead\"").expect("dead");
    let rl: VerificationResult = serde_json::from_str("\"rate_limited\"").expect("rate_limited");
    let skipped: VerificationResult = serde_json::from_str("\"skipped\"").expect("skipped");
    assert_eq!(live, VerificationResult::Live);
    assert_eq!(dead, VerificationResult::Dead);
    assert_eq!(rl, VerificationResult::RateLimited);
    assert_eq!(skipped, VerificationResult::Skipped);
    // Adversarial: a bogus tag must NOT silently resolve to any real verdict.
    let bogus: Result<VerificationResult, _> = serde_json::from_str("\"totally_live\"");
    assert!(
        bogus.is_err(),
        "unknown verdict tag must fail to deserialize"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Group B, transport-failure reason strings (the Error(...) payloads emitted
// by the timeout / connect / redirect / request-failed / body / refusal paths).
// ────────────────────────────────────────────────────────────────────────────

/// The timeout reason leads with the legacy `timeout:` phrase and stays fully
/// actionable: it names the `--timeout` knob and carries a `Fix:`.
#[test]
fn timeout_error_leads_with_legacy_phrase_and_is_actionable() {
    assert!(
        TIMEOUT_ERROR.starts_with("timeout:"),
        "timeout reason must lead with the legacy `timeout:` phrase for substring compat"
    );
    assert!(TIMEOUT_ERROR.contains("--timeout"));
    assert!(TIMEOUT_ERROR.contains("Fix:"));
    // Negative twin: a timeout is an actionable failure, never a `blocked:` refusal.
    assert!(!TIMEOUT_ERROR.starts_with("blocked:"));
}

/// The connect-failure reason leads with `connection failed:` and points at the
/// DNS / firewall / proxy causes; it is distinct from the timeout reason.
#[test]
fn connection_failed_error_leads_with_legacy_phrase() {
    assert!(CONNECTION_FAILED_ERROR.starts_with("connection failed:"));
    assert!(CONNECTION_FAILED_ERROR.contains("DNS"));
    assert!(CONNECTION_FAILED_ERROR.contains("Fix:"));
    assert_ne!(CONNECTION_FAILED_ERROR, TIMEOUT_ERROR);
}

/// Redirect-disabled and generic request-failure are two separate transport
/// verdicts and must not collapse into one another or share a lead phrase.
#[test]
fn redirect_and_request_failed_are_distinct_and_prefixed() {
    assert!(REDIRECT_LIMIT_ERROR.starts_with("too many redirects:"));
    assert!(REQUEST_FAILED_ERROR.starts_with("request failed:"));
    assert_ne!(REDIRECT_LIMIT_ERROR, REQUEST_FAILED_ERROR);
    assert!(REDIRECT_LIMIT_ERROR.contains("Fix:"));
    assert!(REQUEST_FAILED_ERROR.contains("Fix:"));
}

/// The `blocked:` refusal family (SSRF private-URL, HTTPS-only, empty-DNS) is
/// the fail-closed outcome, terse, uniformly prefixed, and deliberately
/// carrying NO `Fix:`, because the refusal itself is the correct result.
#[test]
fn refusal_family_is_blocked_prefixed_with_no_fix() {
    assert_eq!(PRIVATE_URL_ERROR, "blocked: private URL");
    assert_eq!(HTTPS_ONLY_ERROR, "blocked: HTTPS only");
    assert_eq!(DNS_NO_ADDRESSES_ERROR, "blocked: DNS returned no addresses");
    for refusal in [PRIVATE_URL_ERROR, HTTPS_ONLY_ERROR, DNS_NO_ADDRESSES_ERROR] {
        assert!(
            refusal.starts_with("blocked:"),
            "refusal must be blocked-prefixed: {refusal}"
        );
        assert!(
            !refusal.contains("Fix:"),
            "refusal must NOT carry a Fix: {refusal}"
        );
    }
}

/// Every transport / body / refusal reason the mapping can emit must be pairwise
/// distinct: an operator has to be able to tell a timeout from a dropped
/// connection from an oversized body. A collision here is a real diagnostics bug.
#[test]
fn all_probe_error_reasons_are_pairwise_distinct() {
    let reasons = [
        TIMEOUT_ERROR,
        CONNECTION_FAILED_ERROR,
        REDIRECT_LIMIT_ERROR,
        REQUEST_FAILED_ERROR,
        BODY_READ_FAILED_ERROR,
        RESPONSE_TOO_LARGE_ERROR,
        BODY_NOT_UTF8_ERROR,
        PRIVATE_URL_ERROR,
        HTTPS_ONLY_ERROR,
        DNS_NO_ADDRESSES_ERROR,
    ];
    let unique: HashSet<&&str> = reasons.iter().collect();
    assert_eq!(
        unique.len(),
        reasons.len(),
        "all {} probe error reasons must be distinct",
        reasons.len()
    );
}

/// The three response-body reasons each lead with their legacy short phrase so
/// existing `.contains(...)` gates keep matching (Law 3 substring compat).
#[test]
fn response_body_errors_lead_with_legacy_phrases() {
    assert!(BODY_READ_FAILED_ERROR.starts_with("body read failed:"));
    assert!(RESPONSE_TOO_LARGE_ERROR.starts_with("response body exceeds 1MB limit:"));
    assert!(BODY_NOT_UTF8_ERROR.starts_with("body is not utf-8:"));
    // These are actionable (parseable-body problems), so each carries a Fix:.
    assert!(BODY_READ_FAILED_ERROR.contains("Fix:"));
    assert!(RESPONSE_TOO_LARGE_ERROR.contains("Fix:"));
    assert!(BODY_NOT_UTF8_ERROR.contains("Fix:"));
}

// ────────────────────────────────────────────────────────────────────────────
// Group C (pure helper: the malformed-target-URL reason builder).
// ────────────────────────────────────────────────────────────────────────────

/// `invalid_url_error` preserves the underlying parse error verbatim, leads with
/// the legacy `invalid URL:` phrase, and is actionable (has a `Fix:`, is NOT a
/// terse `blocked:` refusal).
#[test]
fn invalid_url_error_embeds_parse_error_and_is_actionable() {
    let parse_detail = "relative URL without a base";
    let msg = invalid_url_error(parse_detail);
    assert!(
        msg.starts_with("invalid URL:"),
        "must lead with `invalid URL:`: {msg}"
    );
    assert!(
        msg.contains(parse_detail),
        "must embed the underlying parse error: {msg}"
    );
    assert!(msg.contains("Fix:"), "must be actionable with a Fix: {msg}");
    assert!(
        !msg.starts_with("blocked:"),
        "invalid URL is actionable, not a refusal: {msg}"
    );
}

/// Two different parse errors produce two different messages, the reason is not
/// a constant that swallows the underlying cause.
#[test]
fn invalid_url_error_varies_with_the_parse_cause() {
    let a = invalid_url_error("empty host");
    let b = invalid_url_error("invalid port number");
    assert_ne!(a, b);
    assert!(a.contains("empty host"));
    assert!(b.contains("invalid port number"));
}

// ────────────────────────────────────────────────────────────────────────────
// Group D: OOB live-probe error redaction mapping. The interactsh poll URL
// carries the session secret as a query param; transport errors must be reduced
// to a category, while the hand-written non-transport variants pass through.
// ────────────────────────────────────────────────────────────────────────────

/// A non-transport interactsh error (an HTTP-status poll failure) passes through
/// `redact_interactsh_error` unchanged: its Display carries no URL, so the exact
/// operator-facing message is preserved.
#[test]
fn redact_passes_through_non_transport_poll_error_verbatim() {
    let err = InteractshError::Poll {
        status: 403,
        body: "access denied".to_string(),
    };
    let redacted = redact_interactsh_error(&err);
    assert_eq!(redacted, "interactsh poll failed (HTTP 403): access denied");
}

/// The timeout variant (which never embeds a URL) also passes through, rendering
/// the exact deadline it fired on (here a 7-second duration).
#[test]
fn redact_renders_timeout_variant_with_exact_duration() {
    let err = InteractshError::Timeout(Duration::from_secs(7));
    let redacted = redact_interactsh_error(&err);
    assert_eq!(redacted, "interactsh request timed out after 7s");
}

/// A register-failure and a poll-failure at the same status must remain
/// distinguishable after redaction (the phase (`register` vs `poll`) survives).
#[test]
fn redact_keeps_register_and_poll_phases_distinct() {
    let register = redact_interactsh_error(&InteractshError::Register {
        status: 500,
        body: "boom".to_string(),
    });
    let poll = redact_interactsh_error(&InteractshError::Poll {
        status: 500,
        body: "boom".to_string(),
    });
    assert_eq!(register, "interactsh register failed (HTTP 500): boom");
    assert_eq!(poll, "interactsh poll failed (HTTP 500): boom");
    assert_ne!(register, poll);
}
