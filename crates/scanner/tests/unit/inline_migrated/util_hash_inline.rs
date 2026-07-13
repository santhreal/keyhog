//! Migrated from src/util_hash.rs. FNV-1a reference vectors and the
//! memoize-by-hash compute-once / wholesale-evict semantics (KH-GAP-004).

use keyhog_scanner::testing::{hash_fast, memoize_by_hash};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;

#[test]
fn hash_fast_matches_reference_fnv1a() {
    // Verifies the seed/prime are the canonical FNV-1a 64-bit constants so a
    // future edit cannot silently re-key the caches that depend on them.
    assert_eq!(hash_fast(b""), 0xcbf29ce484222325);
    // FNV-1a("a") = 0xaf63dc4c8601ec8c (published reference vector).
    assert_eq!(hash_fast(b"a"), 0xaf63dc4c8601ec8c);
    // FNV-1a("foobar") = 0x85944171f73967e8 (published reference vector).
    assert_eq!(hash_fast(b"foobar"), 0x85944171f73967e8);
}

thread_local! {
    static TEST_CACHE: RefCell<HashMap<u64, u32>> = RefCell::new(HashMap::new());
}

#[test]
fn memoize_computes_once_then_caches() {
    let calls = Cell::new(0u32);
    let key = hash_fast(b"payload");

    let first = memoize_by_hash(&TEST_CACHE, key, 16, || {
        calls.set(calls.get() + 1);
        42
    });
    let second = memoize_by_hash(&TEST_CACHE, key, 16, || {
        calls.set(calls.get() + 1);
        99
    });

    assert_eq!(first, 42);
    assert_eq!(
        second, 42,
        "second lookup must hit the cache, not recompute"
    );
    assert_eq!(
        calls.get(),
        1,
        "compute must run exactly once for a repeat key"
    );
}

#[test]
fn memoize_evicts_wholesale_at_capacity() {
    thread_local! {
        static CAP_CACHE: RefCell<HashMap<u64, u32>> = RefCell::new(HashMap::new());
    }
    // Fill to capacity, then insert one past it; the wholesale clear means the
    // map never exceeds `max_entries` live keys.
    for i in 0..3u64 {
        memoize_by_hash(&CAP_CACHE, i, 3, || i as u32);
    }
    memoize_by_hash(&CAP_CACHE, 99, 3, || 99);
    let len = CAP_CACHE.with(|c| c.borrow().len());
    assert!(
        len <= 3,
        "cache must stay bounded by max_entries, got {len}"
    );
}
