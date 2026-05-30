//! Shared non-cryptographic hash + content-keyed memoization primitives.
//!
//! Six byte-identical FNV-1a loops and five verbatim thread-local FNV-keyed
//! caches had accumulated across the crate (decode pipeline dedup, entropy
//! caching, ML-score caching, decode-structure verdict caching). Six copies of
//! one primitive means a hash/seed change silently re-keys only some of the
//! caches, so this module is the single home for both:
//!
//!   * [`hash_fast`] - FNV-1a over a byte slice, the one seed every cache keys
//!     on (was `decode::pipeline::extractor::hash_fast`).
//!   * [`memoize_by_hash`] - the thread-local bounded-cache pattern that every
//!     pure content -> value verdict shared, factored to one generic helper.
//!
//! FNV-1a is chosen for the same reason throughout: ~100x faster than SHA-256
//! for the small (<=1KB) credential-sized inputs these caches key on, with
//! collision rates far below the per-scan entry counts.

use std::cell::RefCell;
use std::collections::HashMap;

/// FNV-1a hash of `data`. Non-cryptographic; used as a content key for dedup
/// and memoization across the scanner. Keep the seed/prime in sync here only -
/// every cache that keys on this depends on the value being identical.
#[inline]
#[must_use]
pub fn hash_fast(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Default ceiling for [`memoize_by_hash`] caches: cleared wholesale when this
/// many distinct keys accumulate, bounding memory under adversarial input.
pub const DEFAULT_MAX_CACHE_ENTRIES: usize = 4096;

/// Look up `key` in a thread-local `HashMap<u64, T>`, computing and inserting
/// the value via `compute` on a miss.
///
/// This is the shared form of the bounded-cache idiom that had been copy-pasted
/// across `entropy::shannon_entropy`, `ml_scorer::score_with_config`,
/// `decode_structure::is_encoded_binary` /
/// `decode_structure::decoded_is_base64_blob` /
/// `decode_structure::decoded_contains_placeholder`. Eviction is wholesale (the
/// whole map is cleared once it reaches `max_entries`) - simple and bounded,
/// matching the prior behavior of every site.
///
/// `cache` must be a distinct thread-local per call site so verdicts of one
/// kind never collide with another. `T: Copy` keeps the value cheap to return
/// without re-borrowing the map.
#[inline]
pub fn memoize_by_hash<T: Copy>(
    cache: &'static std::thread::LocalKey<RefCell<HashMap<u64, T>>>,
    key: u64,
    max_entries: usize,
    compute: impl FnOnce() -> T,
) -> T {
    cache.with(|cache| {
        if let Some(&cached) = cache.borrow().get(&key) {
            return cached;
        }
        let value = compute();
        let mut cache = cache.borrow_mut();
        if cache.len() >= max_entries {
            cache.clear();
        }
        cache.insert(key, value);
        value
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        use std::cell::Cell;
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
        assert_eq!(second, 42, "second lookup must hit the cache, not recompute");
        assert_eq!(calls.get(), 1, "compute must run exactly once for a repeat key");
    }

    #[test]
    fn memoize_evicts_wholesale_at_capacity() {
        thread_local! {
            static CAP_CACHE: RefCell<HashMap<u64, u32>> = RefCell::new(HashMap::new());
        }
        // Fill to capacity, then insert one past it; the wholesale clear means
        // the map never exceeds `max_entries` live keys.
        for i in 0..3u64 {
            memoize_by_hash(&CAP_CACHE, i, 3, || i as u32);
        }
        memoize_by_hash(&CAP_CACHE, 99, 3, || 99);
        let len = CAP_CACHE.with(|c| c.borrow().len());
        assert!(len <= 3, "cache must stay bounded by max_entries, got {len}");
    }
}
