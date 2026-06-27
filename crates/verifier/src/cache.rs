//! Verification cache: avoids re-verifying the same credential across scans.
//!
//! Stores `(credential_hash, detector_id) -> (result, expiry)` mappings.
//! TTLs matter because live/dead status changes over time, and the cache stores
//! only hashes so plaintext credentials are not retained in memory longer than needed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use keyhog_core::{sha256_hash, CredentialHash, VerificationResult};

/// Bounded in-memory cache for verification outcomes.
///
/// # Examples
///
/// ```rust
/// use keyhog_verifier::testing::{
///     TestVerificationCache as VerificationCache, VerifierTestCache,
/// };
/// use std::time::Duration;
///
/// let cache = VerificationCache::new(Duration::from_secs(60));
/// assert!(cache.is_empty());
/// ```
pub(crate) struct VerificationCache {
    /// Sharded concurrent map. DashMap (per-shard locking, default 64 shards
    /// based on parallelism) replaces the previous single global RwLock so
    /// concurrent `get`/`put` calls touch different shards and never block
    /// each other on cacheline bouncing - see the internal design notes.
    entries: DashMap<CacheKey, CacheEntry>,
    inserts: AtomicUsize,
    max_entries: usize,
    ttl: Duration,
    /// Concurrent FIFO queue for fast eviction of the oldest entries
    /// without locking all DashMap shards.
    queue: parking_lot::Mutex<std::collections::VecDeque<CacheKey>>,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct CacheKey {
    credential_hash: CredentialHash,
    detector_id_hash: CredentialHash,
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
    const MAX_METADATA_ENTRIES: usize = 16;
    const MAX_METADATA_KEY_BYTES: usize = 64;
    const MAX_METADATA_VALUE_BYTES: usize = 256;

    /// Create a new cache with the given TTL.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::testing::{
    ///     TestVerificationCache as VerificationCache, VerifierTestCache,
    /// };
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// assert!(cache.is_empty());
    /// ```
    pub(crate) fn new(ttl: Duration) -> Self {
        Self::with_max_entries(ttl, Self::DEFAULT_MAX_ENTRIES)
    }

    /// Create a new cache with the given TTL and an explicit size bound.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::testing::{
    ///     TestVerificationCache as VerificationCache, VerifierTestCache,
    /// };
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::with_max_entries(Duration::from_secs(60), 32);
    /// assert!(cache.is_empty());
    /// ```
    pub(crate) fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: DashMap::new(),
            inserts: AtomicUsize::new(0),
            max_entries: max_entries.max(1),
            ttl,
            queue: parking_lot::Mutex::new(std::collections::VecDeque::new()),
        }
    }

    /// Default cache: 5 minute TTL.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::testing::{
    ///     TestVerificationCache as VerificationCache, VerifierTestCache,
    /// };
    ///
    /// let cache = VerificationCache::default_ttl();
    /// assert!(cache.is_empty());
    /// ```
    pub(crate) fn default_ttl() -> Self {
        Self::new(Duration::from_secs(Self::DEFAULT_TTL_SECS))
    }

    /// Look up a cached result.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::VerificationResult;
    /// use keyhog_verifier::testing::{
    ///     TestVerificationCache as VerificationCache, VerifierTestCache,
    /// };
    /// use std::collections::HashMap;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// cache.put("secret", "detector", VerificationResult::Live, HashMap::new());
    /// assert!(cache.get("secret", "detector").is_some());
    /// ```
    pub(crate) fn get(
        &self,
        credential: &str,
        detector_id: &str,
    ) -> Option<(VerificationResult, HashMap<String, String>)> {
        let key = cache_key(credential, detector_id);
        let now = Instant::now();

        // Per-shard read: O(1) hash, lock just one shard. Hot path for
        // unexpired entries. `?` on `Option` returns None for a miss; an
        // expired hit falls through to the eviction path below.
        let entry = self.entries.get(&key)?;
        if now < entry.expires_at {
            return Some((entry.result.clone(), entry.metadata.clone()));
        }
        drop(entry);

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
    /// use keyhog_verifier::testing::{
    ///     TestVerificationCache as VerificationCache, VerifierTestCache,
    /// };
    /// use std::collections::HashMap;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// cache.put("secret", "detector", VerificationResult::Live, HashMap::new());
    /// assert_eq!(cache.len(), 1);
    /// ```
    pub(crate) fn put(
        &self,
        credential: &str,
        detector_id: &str,
        result: VerificationResult,
        metadata: HashMap<String, String>,
    ) {
        let key = cache_key(credential, detector_id);

        let insert_count = self.inserts.fetch_add(1, Ordering::Relaxed) + 1;
        if insert_count.is_multiple_of(Self::EVICTION_INTERVAL) {
            // Every `EVICTION_INTERVAL`-th insert, sweep TTL-expired entries and
            // reconcile the FIFO queue (drop now-dead keys, trim to `max_entries`).
            // Plain periodic bookkeeping, not a memory-safety invariant - the hard
            // `max_entries` ceiling is enforced unconditionally by the eviction
            // loop after every insert below.
            self.evict_expired();
        }

        let replaced = self
            .entries
            .insert(
                key.clone(),
                CacheEntry {
                    result,
                    metadata: sanitize_metadata(metadata),
                    expires_at: Instant::now() + self.ttl,
                },
            )
            .is_some();
        if !replaced {
            self.queue.lock().push_back(key);
        }

        self.enforce_max_entries_bound();
    }

    /// Number of live or pending FIFO keys. Test-only visibility through the
    /// verifier facade proves the eviction queue stays bounded alongside the map.
    pub(crate) fn queue_len(&self) -> usize {
        self.queue.lock().len()
    }

    /// Number of cached entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::testing::{
    ///     TestVerificationCache as VerificationCache, VerifierTestCache,
    /// };
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// assert_eq!(cache.len(), 0);
    /// ```
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` when the cache contains no live entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::testing::{
    ///     TestVerificationCache as VerificationCache, VerifierTestCache,
    /// };
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// assert!(cache.is_empty());
    /// ```
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict expired entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::testing::{
    ///     TestVerificationCache as VerificationCache, VerifierTestCache,
    /// };
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// cache.evict_expired();
    /// assert!(cache.is_empty());
    /// ```
    pub(crate) fn evict_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| now < entry.expires_at);
        self.reconcile_queue_with_entries();
    }

    pub(crate) fn enforce_max_entries_bound(&self) {
        while self.entries.len() > self.max_entries {
            if !self.evict_one_oldest() && !self.evict_any_entry() {
                break;
            }
        }
    }

    fn reconcile_queue_with_entries(&self) {
        let mut queue = self.queue.lock();
        queue.retain(|key| self.entries.contains_key(key));
        while queue.len() > self.max_entries {
            if let Some(key) = queue.pop_front() {
                self.entries.remove(&key);
            } else {
                break;
            }
        }
    }

    fn evict_one_oldest(&self) -> bool {
        let mut queue = self.queue.lock();
        while let Some(key) = queue.pop_front() {
            if self.entries.remove(&key).is_some() {
                return true;
            }
        }
        false
    }

    fn evict_any_entry(&self) -> bool {
        let key = self.entries.iter().next().map(|entry| entry.key().clone());
        match key {
            Some(key) => self.entries.remove(&key).is_some(),
            None => false,
        }
    }

    pub(crate) fn clear_eviction_queue_for_test(&self) {
        self.queue.lock().clear();
    }

    pub(crate) fn insert_unqueued_for_test(
        &self,
        credential: &str,
        detector_id: &str,
        result: VerificationResult,
        metadata: HashMap<String, String>,
    ) {
        self.entries.insert(
            cache_key(credential, detector_id),
            CacheEntry {
                result,
                metadata: sanitize_metadata(metadata),
                expires_at: Instant::now() + self.ttl,
            },
        );
    }
}

fn cache_key(credential: &str, detector_id: &str) -> CacheKey {
    CacheKey {
        credential_hash: sha256_hash(credential),
        detector_id_hash: sha256_hash(detector_id),
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
