//! The verification cache must hold only STABLE verdicts. A `RateLimited` (429,
//! always transient) or a transient-network `Error` (timeout/reset/"max retries
//! exceeded") that exhausted the retry loop must never be pinned for the full
//! cache TTL, otherwise a single network blip reports a live credential as
//! errored on every rescan within the window. Deterministic config errors are
//! cheap, network-free local recomputes, so they are not cached either.
//!
//! These tests pin the `verification_result_is_cacheable` policy directly and
//! exercise it against the real cache the way the verify orchestrator gates its
//! `put` (`if cacheable { cache.put(...) }`), proving the cache cannot be
//! poisoned by a transient outcome.

use keyhog_core::VerificationResult;
use keyhog_verifier::testing::{
    TestApi, TestVerificationCache as Cache, VerifierTestApi, VerifierTestCache,
};
use std::collections::HashMap;
use std::time::Duration;

fn cacheable(result: VerificationResult) -> bool {
    TestApi.verification_result_is_cacheable_for_test(&result)
}

/// Emulate the verify orchestrator's gated insert.
fn maybe_cache(cache: &Cache, cred: &str, det: &str, result: VerificationResult) {
    if TestApi.verification_result_is_cacheable_for_test(&result) {
        cache.put(cred, det, result, HashMap::new());
    }
}

// ── policy predicate: stable verdicts are cacheable ─────────────────────────

#[test]
fn live_is_cacheable() {
    assert!(cacheable(VerificationResult::Live));
}

#[test]
fn dead_is_cacheable() {
    assert!(cacheable(VerificationResult::Dead));
}

#[test]
fn revoked_is_cacheable() {
    assert!(cacheable(VerificationResult::Revoked));
}

#[test]
fn unverifiable_is_cacheable() {
    assert!(cacheable(VerificationResult::Unverifiable));
}

#[test]
fn skipped_is_cacheable() {
    assert!(cacheable(VerificationResult::Skipped));
}

// ── policy predicate: transient / error outcomes are NOT cacheable ──────────

#[test]
fn rate_limited_is_not_cacheable() {
    assert!(!cacheable(VerificationResult::RateLimited));
}

#[test]
fn error_empty_message_is_not_cacheable() {
    assert!(!cacheable(VerificationResult::Error(String::new())));
}

#[test]
fn error_transient_network_message_is_not_cacheable() {
    assert!(!cacheable(VerificationResult::Error(
        "body read failed".into()
    )));
}

#[test]
fn error_max_retries_exceeded_is_not_cacheable() {
    assert!(!cacheable(VerificationResult::Error(
        "max retries exceeded".into()
    )));
}

#[test]
fn error_deterministic_config_message_is_not_cacheable() {
    // Even a deterministic error is not cached: it is a cheap local recompute,
    // and never caching Error removes any risk of pinning a misclassified blip.
    assert!(!cacheable(VerificationResult::Error(
        "blocked: host 'evil.example' is not in the allowlist".into()
    )));
}

#[test]
fn every_error_message_shape_is_not_cacheable() {
    for msg in [
        "",
        "timeout",
        "connection reset",
        "invalid verify URL",
        "500",
    ] {
        assert!(
            !cacheable(VerificationResult::Error(msg.to_string())),
            "Error({msg:?}) must not be cacheable"
        );
    }
}

// ── end-to-end: the gated insert stores verdicts, refuses transients ────────

#[test]
fn cache_stores_live_verdict() {
    let cache = Cache::new(Duration::from_secs(60));
    maybe_cache(&cache, "cred", "det", VerificationResult::Live);
    assert_eq!(cache.len(), 1);
    assert!(matches!(
        cache.get("cred", "det"),
        Some((VerificationResult::Live, _))
    ));
}

#[test]
fn cache_stores_dead_verdict() {
    let cache = Cache::new(Duration::from_secs(60));
    maybe_cache(&cache, "cred", "det", VerificationResult::Dead);
    assert!(matches!(
        cache.get("cred", "det"),
        Some((VerificationResult::Dead, _))
    ));
}

#[test]
fn cache_stores_revoked_verdict() {
    let cache = Cache::new(Duration::from_secs(60));
    maybe_cache(&cache, "cred", "det", VerificationResult::Revoked);
    assert!(matches!(
        cache.get("cred", "det"),
        Some((VerificationResult::Revoked, _))
    ));
}

#[test]
fn cache_stores_unverifiable_verdict() {
    let cache = Cache::new(Duration::from_secs(60));
    maybe_cache(&cache, "cred", "det", VerificationResult::Unverifiable);
    assert!(matches!(
        cache.get("cred", "det"),
        Some((VerificationResult::Unverifiable, _))
    ));
}

#[test]
fn cache_stores_skipped_verdict() {
    let cache = Cache::new(Duration::from_secs(60));
    maybe_cache(&cache, "cred", "det", VerificationResult::Skipped);
    assert!(matches!(
        cache.get("cred", "det"),
        Some((VerificationResult::Skipped, _))
    ));
}

#[test]
fn cache_skips_rate_limited() {
    let cache = Cache::new(Duration::from_secs(60));
    maybe_cache(&cache, "cred", "det", VerificationResult::RateLimited);
    assert!(cache.is_empty(), "rate-limited result must not be cached");
    assert!(cache.get("cred", "det").is_none());
}

#[test]
fn cache_skips_transient_error() {
    let cache = Cache::new(Duration::from_secs(60));
    maybe_cache(
        &cache,
        "cred",
        "det",
        VerificationResult::Error("body read failed".into()),
    );
    assert!(cache.is_empty(), "transient error must not be cached");
}

#[test]
fn cache_skips_max_retries_error() {
    let cache = Cache::new(Duration::from_secs(60));
    maybe_cache(
        &cache,
        "cred",
        "det",
        VerificationResult::Error("max retries exceeded".into()),
    );
    assert!(cache.is_empty());
}

#[test]
fn cache_skips_deterministic_error() {
    let cache = Cache::new(Duration::from_secs(60));
    maybe_cache(
        &cache,
        "cred",
        "det",
        VerificationResult::Error("invalid verify URL".into()),
    );
    assert!(cache.is_empty());
}

#[test]
fn rate_limited_leaves_credential_uncached_for_reverify() {
    // After a transient outcome the credential is absent from the cache, so the
    // orchestrator's cache.get miss forces a fresh verification next scan.
    let cache = Cache::new(Duration::from_secs(60));
    maybe_cache(&cache, "cred", "det", VerificationResult::RateLimited);
    assert!(
        cache.get("cred", "det").is_none(),
        "a rate-limited credential must remain re-verifiable, not pinned"
    );
}

#[test]
fn transient_outcome_does_not_overwrite_a_cached_verdict() {
    // A good verdict already cached must survive a later transient outcome for
    // the same key (the gate refuses to replace it with a non-verdict).
    let cache = Cache::new(Duration::from_secs(60));
    maybe_cache(&cache, "cred", "det", VerificationResult::Live);
    maybe_cache(&cache, "cred", "det", VerificationResult::RateLimited);
    maybe_cache(
        &cache,
        "cred",
        "det",
        VerificationResult::Error("body read failed".into()),
    );
    assert!(
        matches!(
            cache.get("cred", "det"),
            Some((VerificationResult::Live, _))
        ),
        "cached Live verdict must not be clobbered by a later transient outcome"
    );
    assert_eq!(cache.len(), 1);
}

#[test]
fn mixed_results_cache_only_the_verdicts() {
    let cache = Cache::new(Duration::from_secs(60));
    maybe_cache(&cache, "live", "det", VerificationResult::Live);
    maybe_cache(&cache, "rl", "det", VerificationResult::RateLimited);
    maybe_cache(
        &cache,
        "err",
        "det",
        VerificationResult::Error("timeout".into()),
    );
    maybe_cache(&cache, "dead", "det", VerificationResult::Dead);
    assert_eq!(cache.len(), 2, "only the two verdicts are cached");
    assert!(cache.get("live", "det").is_some());
    assert!(cache.get("dead", "det").is_some());
    assert!(cache.get("rl", "det").is_none());
    assert!(cache.get("err", "det").is_none());
}
