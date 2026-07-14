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
fn companion_request_inputs_partition_cache_identity_canonically() {
    let cache = VerificationCache::new(Duration::from_secs(60));
    let companions_a = HashMap::from([
        ("account".into(), "tenant-a".into()),
        ("secret".into(), "companion-a".into()),
    ]);
    let companions_a_reordered = HashMap::from([
        ("secret".into(), "companion-a".into()),
        ("account".into(), "tenant-a".into()),
    ]);
    let companions_b = HashMap::from([
        ("account".into(), "tenant-b".into()),
        ("secret".into(), "companion-b".into()),
    ]);

    cache.put_with_companions(
        "same-primary",
        "paired-detector",
        &companions_a,
        VerificationResult::Live,
        HashMap::from([("owner".into(), "a".into())]),
    );

    let (result, metadata) = cache
        .get_with_companions("same-primary", "paired-detector", &companions_a_reordered)
        .expect("equivalent companion maps must share one request identity");
    assert!(matches!(result, VerificationResult::Live));
    assert_eq!(metadata["owner"], "a");
    assert!(
        cache
            .get_with_companions("same-primary", "paired-detector", &companions_b)
            .is_none(),
        "a different companion secret or tenant must not inherit a cached verdict"
    );
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
fn max_entry_enforcement_progresses_when_fifo_queue_is_empty() {
    let cache = VerificationCache::with_max_entries(Duration::from_secs(60), 1);
    cache.insert_unqueued_for_test("cred1", "det", VerificationResult::Dead, HashMap::new());
    cache.insert_unqueued_for_test("cred2", "det", VerificationResult::Dead, HashMap::new());
    cache.clear_eviction_queue_for_test();

    cache.enforce_max_entries_bound();

    assert!(
        cache.len() <= 1,
        "cache bound enforcement must still make progress when FIFO state is empty; len={}",
        cache.len()
    );
}

#[test]
fn cache_bound_enforcement_has_non_fifo_progress_fallback() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cache.rs"))
        .expect("cache.rs must be readable");
    assert!(
        src.contains("fn evict_any_entry(&self) -> bool"),
        "cache eviction must have a non-FIFO fallback for queue-drift cases"
    );
    assert!(
        src.contains("if !self.evict_one_oldest() && !self.evict_any_entry()"),
        "max-entry enforcement must call the non-FIFO fallback when FIFO eviction makes no progress"
    );
}

#[test]
fn long_detector_ids_do_not_collide_after_shared_prefix() {
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
