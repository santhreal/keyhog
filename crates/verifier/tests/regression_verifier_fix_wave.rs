//! Regression locks for the verifier fix wave:
//!   * retryable-status predicate now has ONE owner (single/multi-step/AWS share it),
//!   * an explicit detector success contract is authoritative over the generic
//!     body_indicates_error backstop (single-step `resolve_live_verdict`),
//!   * the plaintext body-error fallback is negation-aware,
//!   * cache metadata retention is deterministic (identity fields first),
//!   * the inflight-dedup cap bypass is surfaced (loud counter), not silent.

use keyhog_core::SuccessSpec;
use keyhog_verifier::testing::{
    TestApi, TestVerificationCache as VerificationCache, VerifierTestApi, VerifierTestCache,
};
use std::collections::HashMap;
use std::time::Duration;

// ── retryable_http_status: the one shared retry contract ─────────────────────

#[test]
fn retryable_http_status_matches_429_and_500_through_504_only() {
    assert!(TestApi.retryable_http_status_for_test(429));
    assert!(TestApi.retryable_http_status_for_test(500));
    assert!(TestApi.retryable_http_status_for_test(502));
    assert!(TestApi.retryable_http_status_for_test(504));
    assert!(!TestApi.retryable_http_status_for_test(505));
    assert!(!TestApi.retryable_http_status_for_test(499));
    assert!(!TestApi.retryable_http_status_for_test(200));
    assert!(!TestApi.retryable_http_status_for_test(403));
    assert!(!TestApi.retryable_http_status_for_test(400));
}

// ── success contract is authoritative over the generic backstop ──────────────

#[test]
fn success_spec_is_explicit_only_when_a_condition_is_set() {
    assert!(!TestApi.success_spec_is_explicit_for_test(&SuccessSpec::default()));
    assert!(TestApi.success_spec_is_explicit_for_test(&SuccessSpec {
        status: Some(200),
        ..Default::default()
    }));
    assert!(TestApi.success_spec_is_explicit_for_test(&SuccessSpec {
        json_path: Some("/ok".into()),
        ..Default::default()
    }));
    assert!(TestApi.success_spec_is_explicit_for_test(&SuccessSpec {
        body_contains: Some("login".into()),
        ..Default::default()
    }));
}

#[test]
fn explicit_success_body_with_error_field_stays_live() {
    // The bug: a live 200 whose body legitimately carries a populated error-named
    // field (e.g. GitHub `{"errors":[...]}` on a partial-success 200) was flipped
    // Live->Dead. With an explicit success contract matched, the backstop is off.
    let body = r#"{"errors":["scope warning"],"login":"octocat"}"#;
    assert!(
        TestApi.resolve_live_verdict_for_test(true, true, body),
        "an explicit matched success contract must remain Live"
    );
}

#[test]
fn no_success_contract_runs_the_error_backstop() {
    let body = r#"{"errors":["invalid token"]}"#;
    assert!(
        !TestApi.resolve_live_verdict_for_test(true, false, body),
        "with no explicit contract the populated-error backstop flips to Dead"
    );
    assert!(
        TestApi.resolve_live_verdict_for_test(true, false, r#"{"status":"ok"}"#),
        "a benign body with no contract stays Live"
    );
    assert!(
        !TestApi.resolve_live_verdict_for_test(false, true, "irrelevant"),
        "a not-live response is never resurrected"
    );
}

// ── plaintext body-error fallback is negation-aware ──────────────────────────

#[test]
fn plaintext_negated_error_words_do_not_indicate_error() {
    assert!(!TestApi.body_indicates_error_for_test("no errors"));
    assert!(!TestApi.body_indicates_error_for_test("never expired"));
    assert!(!TestApi.body_indicates_error_for_test("0 errors"));
    assert!(!TestApi.body_indicates_error_for_test("error_rate"));
}

#[test]
fn plaintext_real_error_words_still_indicate_error() {
    assert!(TestApi.body_indicates_error_for_test("request error occurred"));
    assert!(TestApi.body_indicates_error_for_test("authentication error"));
    assert!(TestApi.body_indicates_error_for_test("token expired"));
}

// ── cache metadata retention is deterministic, identity fields first ─────────

fn oversized_metadata() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("arn".to_string(), "arn:aws:iam::1:user/x".to_string());
    for i in 0..20 {
        m.insert(format!("n{i:02}"), "v".to_string());
    }
    m
}

fn round_trip(metadata: HashMap<String, String>) -> HashMap<String, String> {
    let cache = VerificationCache::new(Duration::from_secs(3600));
    cache.put(
        "cred",
        "detector",
        keyhog_core::VerificationResult::Live,
        metadata,
    );
    let (_result, stored) = cache
        .get("cred", "detector")
        .expect("entry must be retrievable");
    stored
}

#[test]
fn identity_metadata_survives_the_cap_deterministically() {
    // 21 entries (arn + n00..n19) over the 16 cap: arn (priority) is always kept,
    // the highest-lex noise keys are always dropped (same result every run).
    let first = round_trip(oversized_metadata());
    let second = round_trip(oversized_metadata());
    assert_eq!(first.len(), 16);
    assert!(
        first.contains_key("arn"),
        "arn is an identity field, kept first"
    );
    assert!(!first.contains_key("n19"), "n19 is dropped past the cap");
    assert_eq!(
        first.keys().collect::<std::collections::BTreeSet<_>>(),
        second.keys().collect::<std::collections::BTreeSet<_>>(),
        "the retained key set must be identical across runs"
    );
}

// ── inflight-dedup cap bypass is surfaced, not silent ────────────────────────

#[test]
fn inflight_cap_bypass_increments_a_visible_counter() {
    let a = TestApi.record_inflight_cap_bypass_for_test(10_000);
    let b = TestApi.record_inflight_cap_bypass_for_test(10_000);
    assert_eq!(
        b,
        a + 1,
        "each dedup-cap bypass bumps the surfaced counter by one"
    );
    assert!(a >= 1);
}
