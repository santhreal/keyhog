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

/// FNV-1a offset basis (seed). The ONE place the seed lives — every cache that
/// keys on this hash depends on the value being identical.
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
/// FNV-1a prime. The ONE place the prime lives.
const FNV_PRIME: u64 = 0x100000001b3;

/// FNV-1a hash of `data`. Non-cryptographic; used as a content key for dedup
/// and memoization across the scanner. Keep the seed/prime in sync here only -
/// every cache that keys on this depends on the value being identical.
#[inline]
#[must_use]
pub(crate) fn hash_fast(data: &[u8]) -> u64 {
    let mut h = FnvHasher::new();
    h.write(data);
    h.finish()
}

/// Allocation-free incremental FNV-1a, for content keys composed of MORE THAN
/// ONE slice (e.g. the ML scorer keys on `text` + separator + `context`).
/// Folding the slices into one [`FnvHasher`] is byte-for-byte identical to
/// hashing their concatenation but never allocates the joined buffer — the
/// reason this exists instead of `hash_fast(&[a, b].concat())` on a hot path.
/// Shares the SINGLE seed/prime ([`FNV_OFFSET_BASIS`] / [`FNV_PRIME`]) with
/// [`hash_fast`], so a single-slice `FnvHasher` and `hash_fast` agree (MC-12).
#[derive(Clone, Copy)]
pub(crate) struct FnvHasher {
    hash: u64,
}

impl Default for FnvHasher {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl FnvHasher {
    /// New hasher seeded at the FNV-1a offset basis.
    #[inline]
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            hash: FNV_OFFSET_BASIS,
        }
    }

    /// Fold `data` into the running hash (FNV-1a: xor-then-multiply per byte).
    #[inline]
    pub(crate) fn write(&mut self, data: &[u8]) {
        let mut hash = self.hash;
        for &byte in data {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        self.hash = hash;
    }

    /// The accumulated 64-bit content key.
    #[inline]
    #[must_use]
    pub(crate) fn finish(&self) -> u64 {
        self.hash
    }
}

/// Default ceiling for [`memoize_by_hash`] caches: cleared wholesale when this
/// many distinct keys accumulate, bounding memory under adversarial input.
pub(crate) const DEFAULT_MAX_CACHE_ENTRIES: usize = 4096;

/// Look up `key` in a thread-local `HashMap<u64, T>`, computing and inserting
/// the value via `compute` on a miss.
///
/// This is the shared form of the bounded-cache idiom that had been copy-pasted
/// across `entropy::shannon_entropy`, `ml_scorer::score_with_config`,
/// and `decode_structure::evidence`. Eviction is wholesale (the whole map is
/// cleared once it reaches `max_entries`) - simple and bounded, matching the
/// prior behavior of every site.
///
/// `cache` must be a distinct thread-local per call site so verdicts of one
/// kind never collide with another. `T: Copy` keeps the value cheap to return
/// without re-borrowing the map.
#[inline]
pub(crate) fn memoize_by_hash<T: Copy>(
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
