//! Verification cache: avoids re-verifying the same credential across scans.
//!
//! Stores `(credential_hash, detector_id) -> (result, expiry)` mappings.
//! TTLs matter because live/dead status changes over time, and the cache stores
//! only hashes so plaintext credentials are not retained in memory longer than needed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use keyhog_core::VerificationResult;
use sha2::{Digest, Sha256};

/// Bounded in-memory cache for verification outcomes.
///
/// # Examples
///
/// ```rust
/// use keyhog_verifier::cache::VerificationCache;
/// use std::time::Duration;
///
/// let cache = VerificationCache::new(Duration::from_secs(60));
/// assert!(cache.is_empty());
/// ```
pub struct VerificationCache {
    /// Sharded concurrent map. DashMap (per-shard locking, default 64 shards
    /// based on parallelism) replaces the previous single global RwLock so
    /// concurrent `get`/`put` calls touch different shards and never block
    /// each other on cacheline bouncing — see audits/legendary-2026-04-26.
    entries: DashMap<CacheKey, CacheEntry>,
    inserts: AtomicUsize,
    max_entries: usize,
    ttl: Duration,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct CacheKey {
    credential_hash: [u8; VerificationCache::HASH_BYTES],
    detector_id_hash: [u8; VerificationCache::HASH_BYTES],
    detector_id: Arc<str>,
}

struct CacheEntry {
    result: VerificationResult,
    metadata: HashMap<String, String>,
    expires_at: Instant,
}

impl VerificationCache {
    const DEFAULT_TTL_SECS: u64 = 300;
    const DEFAULT_MAX_ENTRIES: usize = 10_000;
    const EVICTION_INTERVAL: usize = 64;
    pub(crate) const HASH_BYTES: usize = 32;
    const MAX_DETECTOR_ID_BYTES: usize = 128;
    const MAX_METADATA_ENTRIES: usize = 16;
    const MAX_METADATA_KEY_BYTES: usize = 64;
    const MAX_METADATA_VALUE_BYTES: usize = 256;

    /// Create a new cache with the given TTL.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// assert!(cache.is_empty());
    /// ```
    pub fn new(ttl: Duration) -> Self {
        Self::with_max_entries(ttl, Self::DEFAULT_MAX_ENTRIES)
    }

    /// Create a new cache with the given TTL and an explicit size bound.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::with_max_entries(Duration::from_secs(60), 32);
    /// assert!(cache.is_empty());
    /// ```
    pub fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: DashMap::new(),
            inserts: AtomicUsize::new(0),
            max_entries: max_entries.max(1),
            ttl,
        }
    }

    /// Default cache: 5 minute TTL.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::cache::VerificationCache;
    ///
    /// let cache = VerificationCache::default_ttl();
    /// assert!(cache.is_empty());
    /// ```
    pub fn default_ttl() -> Self {
        Self::new(Duration::from_secs(Self::DEFAULT_TTL_SECS))
    }

    /// Look up a cached result.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::VerificationResult;
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::collections::HashMap;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// cache.put("secret", "detector", VerificationResult::Live, HashMap::new());
    /// assert!(cache.get("secret", "detector").is_some());
    /// ```
    pub fn get(
        &self,
        credential: &str,
        detector_id: &str,
    ) -> Option<(VerificationResult, HashMap<String, String>)> {
        let key = cache_key(credential, detector_id);
        let now = Instant::now();

        // Per-shard read: O(1) hash, lock just one shard. Hot path for
        // unexpired entries.
        if let Some(entry) = self.entries.get(&key) {
            if now < entry.expires_at {
                return Some((entry.result.clone(), entry.metadata.clone()));
            }
        } else {
            return None;
        }

        // Expired: lock the shard for removal. dashmap's Entry API gives us
        // CAS-style replacement so concurrent writers don't double-evict.
        if let dashmap::mapref::entry::Entry::Occupied(entry) = self.entries.entry(key) {
            if now >= entry.get().expires_at {
                entry.remove();
            } else {
                let entry = entry.get();
                return Some((entry.result.clone(), entry.metadata.clone()));
            }
        }
        None
    }

    /// Store a verification result.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::VerificationResult;
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::collections::HashMap;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// cache.put("secret", "detector", VerificationResult::Live, HashMap::new());
    /// assert_eq!(cache.len(), 1);
    /// ```
    pub fn put(
        &self,
        credential: &str,
        detector_id: &str,
        result: VerificationResult,
        metadata: HashMap<String, String>,
    ) {
        let key = cache_key(credential, detector_id);

        let insert_count = self.inserts.fetch_add(1, Ordering::Relaxed) + 1;
        if insert_count.is_multiple_of(Self::EVICTION_INTERVAL) {
            // SAFETY: cache bounded by MAX_CACHE_ENTRIES, eviction runs on every 64th
            // insert. In this implementation MAX_CACHE_ENTRIES is the configured
            // max_entries bound, and we also trim back to that bound after each insert.
            self.evict_expired();
        }

        self.entries.insert(
            key,
            CacheEntry {
                result,
                metadata: sanitize_metadata(metadata),
                expires_at: Instant::now() + self.ttl,
            },
        );

        if self.entries.len() > self.max_entries {
            self.evict_one_oldest();
        }
    }

    /// Number of cached entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// assert_eq!(cache.len(), 0);
    /// ```
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` when the cache contains no live entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// assert!(cache.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict expired entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// cache.evict_expired();
    /// assert!(cache.is_empty());
    /// ```
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| now < entry.expires_at);
    }

    fn evict_one_oldest(&self) {
        // Find the oldest expiry across all shards. Cloning the key is fine
        // since CacheKey is small fixed-size hashes + Arc<str>.
        let oldest_key = self
            .entries
            .iter()
            .min_by_key(|entry| entry.value().expires_at)
            .map(|entry| entry.key().clone());
        if let Some(key) = oldest_key {
            self.entries.remove(&key);
        }
    }
}

fn hash_credential(credential: &str) -> [u8; VerificationCache::HASH_BYTES] {
    Sha256::digest(credential.as_bytes()).into()
}

fn cache_key(credential: &str, detector_id: &str) -> CacheKey {
    CacheKey {
        credential_hash: hash_credential(credential),
        detector_id_hash: hash_credential(detector_id),
        detector_id: Arc::<str>::from(truncate_to_char_boundary(
            detector_id,
            VerificationCache::MAX_DETECTOR_ID_BYTES,
        )),
    }
}

fn sanitize_metadata(metadata: HashMap<String, String>) -> HashMap<String, String> {
    metadata
        .into_iter()
        .take(VerificationCache::MAX_METADATA_ENTRIES)
        .map(|(key, value)| {
            (
                truncate_to_char_boundary(&key, VerificationCache::MAX_METADATA_KEY_BYTES),
                truncate_to_char_boundary(&value, VerificationCache::MAX_METADATA_VALUE_BYTES),
            )
        })
        .collect()
}

fn truncate_to_char_boundary(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}
