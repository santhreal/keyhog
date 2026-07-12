//! Verification cache: avoids re-verifying the same credential across scans.
//!
//! Stores `(credential_hash, detector_id) -> (result, expiry)` mappings.
//! TTLs matter because live/dead status changes over time, and the cache stores
//! only hashes so plaintext credentials are not retained in memory longer than needed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
    /// Monotonic insert generation. Each `put` stamps the entry AND its queue
    /// marker with the same generation, so eviction can tell a key's CURRENT
    /// queue position from stale markers left by earlier overwrites.
    generation: AtomicU64,
    /// Concurrent recency queue `(key, generation)` for fast eviction of the
    /// oldest entries without locking all DashMap shards. A key overwritten by
    /// a later `put` leaves its old marker behind (generation mismatch); the
    /// eviction/reconcile paths skip such stale markers lazily instead of
    /// paying an O(queue) reposition on every refresh.
    queue: parking_lot::Mutex<std::collections::VecDeque<(CacheKey, u64)>>,
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
    /// The queue-marker generation this entry was written with; see
    /// [`VerificationCache::generation`].
    generation: u64,
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
            generation: AtomicU64::new(0),
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

        // Stamp the entry and its queue marker with one fresh generation. An
        // overwrite REFRESHES the key's recency: the new marker goes to the
        // back, and the old marker (now generation-mismatched) is skipped
        // lazily by eviction — previously a re-verified credential kept its
        // ORIGINAL queue slot and capacity eviction dropped the freshest
        // entries first, forcing redundant live re-verification.
        let generation = self.generation.fetch_add(1, Ordering::Relaxed);
        self.entries.insert(
            key.clone(),
            CacheEntry {
                result,
                metadata: sanitize_metadata(metadata),
                expires_at: Instant::now() + self.ttl,
                generation,
            },
        );
        let needs_stale_sweep = {
            let mut queue = self.queue.lock();
            queue.push_back((key, generation));
            // Overwrites accumulate stale markers; bound the queue's memory by
            // sweeping once it doubles past the live map (amortized O(1)).
            queue.len() > self.max_entries.saturating_mul(2)
        };
        if needs_stale_sweep {
            self.reconcile_queue_with_entries();
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
        // Keep only CURRENT markers: the key must still be live AND the marker
        // must be the generation of its latest write (stale markers from
        // overwritten entries are dropped here).
        queue.retain(|(key, generation)| {
            self.entries
                .get(key)
                .is_some_and(|entry| entry.generation == *generation)
        });
        while queue.len() > self.max_entries {
            if let Some((key, _)) = queue.pop_front() {
                self.entries.remove(&key);
            } else {
                break;
            }
        }
    }

    fn evict_one_oldest(&self) -> bool {
        let mut queue = self.queue.lock();
        while let Some((key, generation)) = queue.pop_front() {
            // A generation mismatch is a STALE marker: the key was refreshed by
            // a later put and its current marker sits further back. Skip it —
            // evicting here would drop the freshest entry first.
            if self
                .entries
                .remove_if(&key, |_, entry| entry.generation == generation)
                .is_some()
            {
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
                generation: self.generation.fetch_add(1, Ordering::Relaxed),
            },
        );
    }
}

/// One-batch eviction size for a bounded cache that hit its cap: drop the oldest
/// `1/8`, never fewer than one. Single owner for the fraction shared by the
/// DNS-resolution and pinned-client caches so tuning it happens in one place.
/// `pub` (inside the private `cache` module) so the eviction-primitive regression
/// test can assert the `.max(1)` never-zero floor against this single owner;
/// reaches the public API only via the explicit `testing` re-export.
pub fn oldest_eviction_batch(max_entries: usize) -> usize {
    (max_entries / 8).max(1)
}

/// Evict the oldest `count` entries from a bounded age-stamped `DashMap` instead
/// of wiping it wholesale. Shared by the DNS-resolution and pinned-client caches
/// (`ssrf`, `verify::request`) so both bound memory on cap without discarding
/// every still-valid entry and forcing a re-resolve / TLS-client-rebuild storm.
pub(crate) fn evict_oldest_dashmap_entries<K, V>(
    cache: &DashMap<K, V>,
    count: usize,
    age_of: impl Fn(&V) -> Instant,
) where
    K: Eq + std::hash::Hash + Clone,
{
    if count == 0 {
        return;
    }
    let mut by_age: Vec<(K, Instant)> = cache
        .iter()
        .map(|entry| (entry.key().clone(), age_of(entry.value())))
        .collect();
    // We only need the `count` OLDEST entries, not a fully sorted list. When
    // `count < len`, `select_nth_unstable_by_key` partitions the oldest `count`
    // into the prefix in O(n) rather than the O(n log n) full sort the whole
    // cache used to pay on every cap-hit eviction — the lever on a large hot
    // cache. The partition leaves `[0, count)` as the smallest-`Instant` (oldest)
    // entries; their internal order is irrelevant since we remove all of them.
    // Same eviction set as the old sort (ties at the boundary are arbitrary in
    // both), just without ordering the tail we immediately discard.
    if count < by_age.len() {
        by_age.select_nth_unstable_by_key(count, |(_, inserted_at)| *inserted_at);
        by_age.truncate(count);
    }
    for (key, _) in by_age {
        cache.remove(&key);
    }
}

fn cache_key(credential: &str, detector_id: &str) -> CacheKey {
    CacheKey {
        credential_hash: sha256_hash(credential),
        detector_id_hash: sha256_hash(detector_id),
    }
}

/// Identity/high-value metadata keys retained first when a finding's metadata
/// exceeds `MAX_METADATA_ENTRIES`. Ordering is stable so the SAME oversized
/// metadata map always keeps the SAME entries run-to-run (a bare `HashMap`
/// iterator `.take(16)` kept an arbitrary, nondeterministic subset — `arn`
/// could survive one scan and vanish the next).
const PRIORITY_METADATA_KEYS: &[&str] = &[
    "arn",
    "account_id",
    "user_id",
    "oob_observed",
    "oob_unique_id",
    "oob_protocol",
    "oob_remote_address",
];

fn metadata_priority_rank(key: &str) -> usize {
    PRIORITY_METADATA_KEYS
        .iter()
        .position(|k| *k == key)
        .map_or(PRIORITY_METADATA_KEYS.len(), |rank| rank)
}

fn sanitize_metadata(metadata: HashMap<String, String>) -> HashMap<String, String> {
    let mut entries: Vec<(String, String)> = metadata.into_iter().collect();
    // Priority keys first, then lexicographic — total order, so retention is
    // deterministic and identity fields are never dropped in favor of noise.
    entries.sort_unstable_by(|(a, _), (b, _)| {
        metadata_priority_rank(a)
            .cmp(&metadata_priority_rank(b))
            .then_with(|| a.cmp(b))
    });
    entries
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
