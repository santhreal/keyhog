use keyhog_core::VerificationResult;
use keyhog_verifier::cache::VerificationCache;
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
    cache.put("cred", "det", VerificationResult::Dead, HashMap::new());
    std::thread::sleep(Duration::from_millis(2));
    cache.evict_expired();
    assert!(cache.is_empty());
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
