use keyhog_core::VerificationResult;
use keyhog_verifier::testing::{TestVerificationCache as VerificationCache, VerifierTestCache};
use std::collections::HashMap;
use std::time::Duration;

#[test]
fn cache_hit_and_miss() {
    let cache = VerificationCache::new(Duration::from_secs(60));

    assert!(cache.get("cred1", "detector1").is_none());
    cache.put(
        "cred1",
        "detector1",
        VerificationResult::Live,
        HashMap::from([("user".into(), "alice".into())]),
    );

    let (result, metadata) = cache.get("cred1", "detector1").unwrap();
    assert!(matches!(result, VerificationResult::Live));
    assert_eq!(metadata["user"], "alice");
    assert!(cache.get("cred1", "detector2").is_none());
}

#[test]
fn cache_ttl_expiry() {
    let cache = VerificationCache::new(Duration::from_millis(1));
    cache.put("cred", "det", VerificationResult::Dead, HashMap::new());
    std::thread::sleep(Duration::from_millis(2));
    assert!(cache.get("cred", "det").is_none());
}

#[test]
fn evict_expired() {
    let cache = VerificationCache::new(Duration::from_millis(1));
    // Insert TWO entries - one we let expire, one we insert AFTER the
    // sleep so it's still fresh when evict_expired runs. Pre-fix the
    // assertion was just `is_empty()`, which would still pass on a
    // bug that removed every entry regardless of TTL.
    cache.put(
        "cred-expired",
        "det",
        VerificationResult::Dead,
        HashMap::new(),
    );
    std::thread::sleep(Duration::from_millis(2));
    cache.put(
        "cred-fresh",
        "det",
        VerificationResult::Dead,
        HashMap::new(),
    );
    cache.evict_expired();
    // The expired entry must be GONE; the fresh entry must STILL be in
    // the cache. is_empty() conflated these two cases.
    assert!(
        cache.get("cred-expired", "det").is_none(),
        "expired entry must be evicted"
    );
    assert!(
        cache.get("cred-fresh", "det").is_some(),
        "fresh entry must survive evict_expired (would fail if evict \
         dropped all entries regardless of TTL)"
    );
    assert_eq!(
        cache.len(),
        1,
        "cache should contain exactly the fresh entry"
    );
}

#[test]
fn evicts_oldest_entry_when_cache_hits_capacity() {
    let cache = VerificationCache::with_max_entries(Duration::from_secs(60), 2);
    cache.put("cred1", "det", VerificationResult::Dead, HashMap::new());
    std::thread::sleep(Duration::from_millis(1));
    cache.put("cred2", "det", VerificationResult::Dead, HashMap::new());
    std::thread::sleep(Duration::from_millis(1));
    cache.put("cred3", "det", VerificationResult::Dead, HashMap::new());

    assert!(cache.get("cred1", "det").is_none());
    assert!(cache.get("cred2", "det").is_some());
    assert!(cache.get("cred3", "det").is_some());
    assert_eq!(cache.len(), 2);
}

#[test]
fn eviction_queue_stays_bounded_when_ttl_keeps_entry_map_under_capacity() {
    let cache = VerificationCache::with_max_entries(Duration::from_secs(0), 10_000);

    for idx in 0..512 {
        cache.put(
            &format!("cred-{idx}"),
            "det",
            VerificationResult::Dead,
            HashMap::new(),
        );
    }

    assert!(
        cache.len() <= 64,
        "zero-TTL map should stay under one eviction interval; got {} live entries",
        cache.len()
    );
    assert!(
        cache.queue_len() <= 64,
        "eviction queue must stay bounded with expired entries; got {} queued keys",
        cache.queue_len()
    );
}

#[test]
fn long_detector_ids_do_not_collide_after_truncation_boundary() {
    let cache = VerificationCache::new(Duration::from_secs(60));
    let shared_prefix = "x".repeat(128);
    let detector_a = format!("{shared_prefix}alpha");
    let detector_b = format!("{shared_prefix}beta");

    cache.put(
        "cred",
        &detector_a,
        VerificationResult::Live,
        HashMap::from([("source".into(), "a".into())]),
    );
    cache.put(
        "cred",
        &detector_b,
        VerificationResult::Dead,
        HashMap::from([("source".into(), "b".into())]),
    );

    let (result_a, metadata_a) = cache.get("cred", &detector_a).unwrap();
    let (result_b, metadata_b) = cache.get("cred", &detector_b).unwrap();
    assert!(matches!(result_a, VerificationResult::Live));
    assert!(matches!(result_b, VerificationResult::Dead));
    assert_eq!(metadata_a["source"], "a");
    assert_eq!(metadata_b["source"], "b");
}
