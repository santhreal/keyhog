use keyhog_core::VerificationResult;
use keyhog_verifier::cache::VerificationCache;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn test_cache_zero_ttl() {
    let cache = VerificationCache::with_max_entries(Duration::from_secs(0), 100);
    cache.put("cred", "det", VerificationResult::Live, HashMap::new());
    assert!(
        cache.get("cred", "det").is_none(),
        "Zero TTL should expire instantly"
    );
}

#[test]
fn test_cache_massive_entries_eviction() {
    let cache = VerificationCache::with_max_entries(Duration::from_secs(60), 5);
    for i in 0..10 {
        cache.put(
            &format!("cred{}", i),
            "det",
            VerificationResult::Live,
            HashMap::new(),
        );
    }
    assert!(
        cache.len() <= 5,
        "Cache length should not exceed max_entries"
    );
}

#[test]
fn test_cache_zero_max_entries() {
    let cache = VerificationCache::with_max_entries(Duration::from_secs(60), 0);
    cache.put("cred", "det", VerificationResult::Live, HashMap::new());
    assert!(
        cache.len() <= 1,
        "Cache length should be at most 1 for zero capacity"
    );
}

#[test]
fn test_cache_concurrent_access() {
    let cache = Arc::new(VerificationCache::with_max_entries(
        Duration::from_secs(60),
        1000,
    ));
    let mut threads = vec![];
    for i in 0..8 {
        let cache_clone = cache.clone();
        threads.push(std::thread::spawn(move || {
            for j in 0..100 {
                cache_clone.put(
                    &format!("cred_{}_{}", i, j),
                    "det",
                    VerificationResult::Live,
                    HashMap::new(),
                );
                let _ = cache_clone.get(&format!("cred_{}_{}", i, j), "det");
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
    assert!(
        cache.len() <= 1000,
        "Cache should handle concurrent puts and gets"
    );
}

#[test]
fn test_cache_max_u64_ttl() {
    // Adding u64::MAX to Instant::now() panics in standard library std::time::Instant.
    // Instead of forcing a panic here, we isolate the crash or just use a very large but safe TTL.
    // However, since it is an adversarial test, let's isolate it with std::process::Command to test if it panics.
}

#[test]
fn test_cache_empty_strings() {
    let cache = VerificationCache::with_max_entries(Duration::from_secs(60), 100);
    cache.put("", "", VerificationResult::Live, HashMap::new());
    assert!(
        cache.get("", "").is_some(),
        "Empty string cache key should be valid"
    );
}

#[test]
fn test_cache_massive_metadata() {
    let cache = VerificationCache::with_max_entries(Duration::from_secs(60), 100);
    let mut meta = HashMap::new();
    meta.insert("a".repeat(100_000), "b".repeat(100_000));
    cache.put("cred", "det", VerificationResult::Live, meta);
    let res = cache.get("cred", "det");
    assert!(res.is_some(), "Should not panic on large metadata");
    let (_, stored_meta) = res.unwrap();
    for (k, v) in stored_meta {
        assert!(k.len() < 100_000, "Key should be truncated");
        assert!(v.len() < 100_000, "Value should be truncated");
    }
}

#[test]
fn test_cache_null_bytes() {
    let cache = VerificationCache::with_max_entries(Duration::from_secs(60), 100);
    cache.put(
        "cred\0\0",
        "det\0",
        VerificationResult::Live,
        HashMap::new(),
    );
    assert!(
        cache.get("cred\0\0", "det\0").is_some(),
        "Null bytes should be handled properly"
    );
    assert!(
        cache.get("cred", "det\0").is_none(),
        "Null byte keys should be distinct"
    );
}

// Use rusty-fork to isolate the panic instead of custom dead-code stubs
rusty_fork::rusty_fork_test! {
    #![rusty_fork(timeout_ms = 5000)]
    #[test]
    #[should_panic]
    fn test_cache_u64_max_ttl_inner() {
        let cache = VerificationCache::with_max_entries(Duration::from_secs(u64::MAX), 100);
        cache.put("cred", "det", VerificationResult::Live, HashMap::new());
        assert!(cache.get("cred", "det").is_some());
    }
}

use keyhog_verifier::rate_limit::RateLimiter;

// RateLimiter::new was hardened to clamp non-finite/non-positive
// rates to a 1.0 r/s safe default (rate_limit.rs:30-35), so
// `should_panic` is the wrong assertion. Contract is now "does
// not panic / does not hang; uses safe default".
rusty_fork::rusty_fork_test! {
    #![rusty_fork(timeout_ms = 5000)]
    #[test]
    fn test_rate_limiter_zero_rate_inner() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let limiter = RateLimiter::new(0.0);
            limiter.wait("test").await;
        });
    }

    #[test]
    fn test_rate_limiter_nan_rate_inner() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let limiter = RateLimiter::new(f64::NAN);
            limiter.wait("test").await;
        });
    }

    #[test]
    fn test_rate_limiter_negative_rate_inner() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let limiter = RateLimiter::new(-5.0);
            limiter.wait("test").await;
        });
    }
}

#[tokio::test]
async fn test_rate_limiter_concurrent_updates() {
    let limiter = Arc::new(RateLimiter::new(5.0));
    let mut handles = vec![];
    for _ in 0..10 {
        let l = limiter.clone();
        handles.push(tokio::spawn(async move {
            l.update_limit("test", 10.0).await;
            l.wait("test").await;
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    // Should not deadlock or panic
    assert!(true, "Concurrent updates and waits should not deadlock");
}

rusty_fork::rusty_fork_test! {
    #![rusty_fork(timeout_ms = 5000)]
    #[test]
    fn test_rate_limiter_extreme_update_inner() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let limiter = RateLimiter::new(5.0);
            limiter.update_limit("test", f64::INFINITY).await;
            limiter.wait("test").await;
        });
    }
}
