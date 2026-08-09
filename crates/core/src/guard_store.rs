//! Durable guard state store: schema, tables, and memory-bounded LRU.
//!
//! This module owns the versioned non-secret guard state storage. It does not
//! store credential values, raw file or blob payloads, matched excerpts,
//! verification request material, or environment variable values.
//!
//! ## Storage engine
//!
//! The proposed durable backend is `redb` (pure-Rust, transactional, embedded).
//! Before finalizing, a focused spike must prove Linux/macOS/Windows/musl
//! builds, atomic transaction behavior under forced termination, file
//! ownership/permission handling, bounded open descriptors, corruption
//! detection, compaction, and deterministic migration failure for unsupported
//! schema versions. Until that spike passes, this module defines the logical
//! schema and the in-memory hot index only.
//!
//! ## Memory bounds
//!
//! The durable store is not loaded wholesale. A configurable in-memory LRU
//! holds hot clean attestations with a default hard budget of 64 MiB. Budget
//! accounting includes keys, paths, allocator overhead estimate, and values.
//! Once full, evict least-recently-used entries from memory; durable entries
//! remain available.

use crate::guard_state::{
    GitCleanAttestation, GitHashAlgorithm, GuardPolicyIdentity, GuardRootRecord,
    GuardRootState, GUARD_SCHEMA_VERSION,
};
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;

/// Default hard memory budget for the hot clean attestation index (64 MiB).
pub const DEFAULT_HOT_INDEX_MEMORY: usize = 64 * 1024 * 1024;

/// Estimated bytes per hot-index entry: key (hash algo + OID hex + policy
/// short digest ≈ 80 bytes) + value (attestation ≈ 200 bytes) + allocator
/// overhead estimate (32 bytes). Conservative: rounds up to 320.
const ESTIMATED_BYTES_PER_ENTRY: usize = 320;

/// Maximum number of hot-index entries under the configured memory budget.
fn max_entries_for_budget(budget: usize) -> NonZeroUsize {
    let n = budget / ESTIMATED_BYTES_PER_ENTRY;
    // At least one entry; if budget is too small, one entry still fits.
    NonZeroUsize::new(n.max(1)).unwrap_or(NonZeroUsize::MIN)
}

/// In-memory LRU cache for hot Git clean attestations.
///
/// This is the hot index: durable entries remain available even after
/// eviction from this cache. The cache bounds memory, not correctness.
pub struct HotAttestationIndex {
    cache: Mutex<LruCache<HotKey, GitCleanAttestation>>,
    budget: usize,
}

/// Key for the hot index: hash algorithm + blob OID + policy short digest.
/// This mirrors the durable lookup key but owns its data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HotKey {
    hash_algorithm: GitHashAlgorithm,
    blob_oid: String,
    policy_short_digest: String,
}

impl HotAttestationIndex {
    /// Create a hot index with the default 64 MiB memory budget.
    pub fn new() -> Self {
        Self::with_budget(DEFAULT_HOT_INDEX_MEMORY)
    }

    /// Create a hot index with a custom memory budget in bytes.
    pub fn with_budget(budget: usize) -> Self {
        let cap = max_entries_for_budget(budget);
        Self {
            cache: Mutex::new(LruCache::new(cap)),
            budget,
        }
    }

    /// Look up a clean attestation by key. A hit does not read blob payload.
    pub fn get(
        &self,
        hash_algorithm: GitHashAlgorithm,
        blob_oid: &str,
        policy_short_digest: &str,
    ) -> Option<GitCleanAttestation> {
        let key = HotKey {
            hash_algorithm,
            blob_oid: blob_oid.to_string(),
            policy_short_digest: policy_short_digest.to_string(),
        };
        self.cache.lock().get(&key).cloned()
    }

    /// Insert a clean attestation. Only complete clean outcomes are
    /// insertable; the caller must not insert findings, gaps, panics, or
    /// incomplete reports.
    pub fn insert(&self, attestation: GitCleanAttestation) {
        let key = HotKey {
            hash_algorithm: attestation.hash_algorithm,
            blob_oid: attestation.blob_oid.clone(),
            policy_short_digest: attestation
                .policy_identity
                .short_digest()
                .unwrap_or_default(),
        };
        self.cache.lock().put(key, attestation);
    }

    /// Remove a single attestation by key.
    pub fn remove(
        &self,
        hash_algorithm: GitHashAlgorithm,
        blob_oid: &str,
        policy_short_digest: &str,
    ) -> Option<GitCleanAttestation> {
        let key = HotKey {
            hash_algorithm,
            blob_oid: blob_oid.to_string(),
            policy_short_digest: policy_short_digest.to_string(),
        };
        self.cache.lock().pop(&key)
    }

    /// Invalidate all attestations whose policy identity is no longer
    /// compatible with the current identity. Returns the count removed.
    pub fn invalidate_for_policy(&self, current: &GuardPolicyIdentity) -> usize {
        let current_short = current.short_digest().unwrap_or_default();
        let mut removed = 0;
        let mut to_remove = Vec::new();
        {
            let cache = self.cache.lock();
            for (key, value) in cache.iter() {
                let key_digest = &key.policy_short_digest;
                let value_digest = value.policy_identity.short_digest().unwrap_or_default();
                if key_digest != &current_short || value_digest != current_short {
                    to_remove.push(key.clone());
                }
            }
        }
        let mut cache = self.cache.lock();
        for key in to_remove {
            if cache.pop(&key).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Current number of entries in the hot index.
    pub fn len(&self) -> usize {
        self.cache.lock().len()
    }

    /// Whether the hot index is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.lock().is_empty()
    }

    /// Configured memory budget in bytes.
    pub fn budget(&self) -> usize {
        self.budget
    }

    /// Clear all entries from the hot index.
    pub fn clear(&self) {
        self.cache.lock().clear();
    }
}

impl Default for HotAttestationIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ── Store schema versioning ──────────────────────────────────────────────

/// Metadata row in the durable store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreMeta {
    /// Schema version of the store.
    pub schema_version: u32,
    /// Unique store identifier.
    pub store_uuid: [u8; 16],
    /// KeyHog version that created the store.
    pub created_version: String,
    /// Last schema version that was successfully migrated.
    pub last_successful_migration: u32,
}

/// Error returned by the guard store.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuardStoreError {
    /// The store schema version is newer than this binary supports.
    #[error("guard store schema version {found} is newer than supported {supported}; upgrade keyhog or run `keyhog guard rebuild <root>`")]
    SchemaTooNew {
        /// Schema version found on disk.
        found: u32,
        /// Maximum schema version this binary supports.
        supported: u32,
    },
    /// The store schema version is older than this binary supports and
    /// cannot be migrated.
    #[error("guard store schema version {found} is no longer supported; run `keyhog guard rebuild <root>` to recreate state")]
    SchemaObsolete {
        /// Schema version found on disk.
        found: u32,
    },
    /// The store file is corrupt or truncated.
    #[error("guard store is corrupt: {detail}; run `keyhog guard rebuild <root>`")]
    Corrupt {
        /// Human-readable corruption detail.
        detail: String,
    },
    /// The store path has unsafe ownership or permissions.
    #[error("guard store path is unsafe: {detail}")]
    UnsafePath {
        /// Human-readable safety violation detail.
        detail: String,
    },
    /// An I/O error occurred.
    #[error("guard store I/O error: {0}")]
    Io(String),
    /// The store was not started cleanly (previous process may not have
    /// flushed).
    #[error("guard store was not closed cleanly; run `keyhog guard reconcile <root>`")]
    UncleanShutdown,
}

/// Check whether a found schema version is compatible with this binary.
pub fn check_schema_version(found: u32) -> Result<(), GuardStoreError> {
    if found > GUARD_SCHEMA_VERSION {
        return Err(GuardStoreError::SchemaTooNew {
            found,
            supported: GUARD_SCHEMA_VERSION,
        });
    }
    if found < 1 {
        return Err(GuardStoreError::SchemaObsolete { found });
    }
    // v1 is the initial schema; no migrations exist yet.
    Ok(())
}

// ── Root registry ────────────────────────────────────────────────────────

/// In-memory root registry. The durable store persists these records; this
/// holds the live state for the daemon scheduler.
#[derive(Debug, Default)]
pub struct RootRegistry {
    roots: std::collections::HashMap<Vec<u8>, GuardRootRecord>,
}

impl RootRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new root. Returns the initial record in `Stopped` state.
    pub fn register(
        &mut self,
        canonical_path: Vec<u8>,
        filesystem_identity: crate::guard_state::FilesystemIdentity,
        mode: crate::guard_state::GuardRootMode,
    ) -> GuardRootRecord {
        let record = GuardRootRecord {
            canonical_path: canonical_path.clone(),
            filesystem_identity,
            mode,
            state: GuardRootState::Stopped,
            terminal_sequence: 0,
            last_receipt: None,
        };
        self.roots.insert(canonical_path, record.clone());
        record
    }

    /// Look up a root by canonical path bytes.
    pub fn get(&self, canonical_path: &[u8]) -> Option<&GuardRootRecord> {
        self.roots.get(canonical_path)
    }

    /// Look up a root by canonical path bytes for mutation.
    pub fn get_mut(&mut self, canonical_path: &[u8]) -> Option<&mut GuardRootRecord> {
        self.roots.get_mut(canonical_path)
    }

    /// Remove a root from the registry.
    pub fn remove(&mut self, canonical_path: &[u8]) -> Option<GuardRootRecord> {
        self.roots.remove(canonical_path)
    }

    /// List all registered roots.
    pub fn list(&self) -> Vec<&GuardRootRecord> {
        self.roots.values().collect()
    }

    /// Number of registered roots.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Count roots by state.
    pub fn count_by_state(&self, state: GuardRootState) -> usize {
        self.roots
            .values()
            .filter(|r| r.state == state)
            .count()
    }
}
