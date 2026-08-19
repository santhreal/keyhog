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
    GitCleanAttestation, GitHashAlgorithm, GuardPolicyIdentity, GuardRootRecord, GuardRootState,
    GUARD_SCHEMA_VERSION,
};
use lru::LruCache;
use parking_lot::Mutex;
use redb::ReadableTable;
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
    #[error("guard store path is unsafe: {detail}; run `keyhog guard repair <root>` or fix directory permissions")]
    UnsafePath {
        /// Human-readable safety violation detail.
        detail: String,
    },
    /// An I/O error occurred.
    #[error("guard store I/O error: {0}; check disk space and permissions or run `keyhog guard repair <root>`")]
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
        filesystem_authority: crate::guard_state::FilesystemAuthority,
        mode: crate::guard_state::GuardRootMode,
    ) -> GuardRootRecord {
        let record = GuardRootRecord {
            canonical_path: canonical_path.clone(),
            filesystem_identity,
            filesystem_authority,
            mode,
            state: GuardRootState::Stopped,
            terminal_sequence: 0,
            accepted_event_sequence: 0,
            completed_event_sequence: 0,
            initial_reconciliation_time: None,
            last_reconciliation_time: None,
            backend_route_label: String::new(),
            last_receipt: None,
        };
        self.roots.insert(canonical_path, record.clone());
        record
    }

    /// Insert a fully-formed root record. Used when restoring from
    /// the durable store, where the complete record state must be
    /// preserved rather than initialized to `Stopped`.
    pub fn insert_record(&mut self, record: GuardRootRecord) {
        self.roots.insert(record.canonical_path.clone(), record);
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
        self.roots.values().filter(|r| r.state == state).count()
    }
}

// ── Durable store (redb) ─────────────────────────────────────────────────

/// redb table definition for the metadata singleton.
const META_TABLE: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("meta");

/// redb table definition for root records, keyed by canonical path bytes.
const ROOTS_TABLE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("roots");

/// redb table definition for Git clean attestations, keyed by
/// (hash_algorithm_label || blob_oid_hex || policy_short_digest).
const ATTESTATIONS_TABLE: redb::TableDefinition<&[u8], &[u8]> =
    redb::TableDefinition::new("git_clean_attestations");

/// redb table definition for root coverage gaps, keyed by
/// (canonical_path || 0x00 || blob_oid). Value is the gap description.
const ROOT_GAPS_TABLE: redb::TableDefinition<&[u8], &[u8]> =
    redb::TableDefinition::new("root_gaps");

/// redb table definition for the service state singleton.
/// Key is "clean_shutdown", value is 1 (clean) or 0 (unclean).
const SERVICE_STATE_TABLE: redb::TableDefinition<&str, u8> =
    redb::TableDefinition::new("service_state");

/// Durable guard state store backed by redb.
///
/// Persists root records and clean attestations to a single file.
/// The in-memory `RootRegistry` and `HotAttestationIndex` remain the
/// hot path; this store provides crash recovery across daemon restarts.
pub struct DurableGuardStore {
    db: redb::Database,
    path: std::path::PathBuf,
}

impl DurableGuardStore {
    /// Open or create the durable store at the given path.
    ///
    /// The path is validated for safety: it must not be a symlink, and
    /// the file (once created) is set to owner-only permissions (0600).
    /// The parent directory is created with 0700 permissions if needed.
    pub fn open(path: &std::path::Path) -> Result<Self, GuardStoreError> {
        // Reject symlinked state paths. A symlink could point outside the
        // intended state directory, leaking guard state to an attacker.
        if path.exists() {
            let meta = std::fs::symlink_metadata(path)
                .map_err(|e| GuardStoreError::Io(format!("stat guard store path: {e}")))?;
            if meta.file_type().is_symlink() {
                return Err(GuardStoreError::Io(
                    "guard store path is a symlink; refusing to open".to_string(),
                ));
            }
        }
        // Create parent directory with owner-only permissions.
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| GuardStoreError::Io(format!("create guard store dir: {e}")))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                        .map_err(|e| {
                            GuardStoreError::Io(format!("set guard store dir perms: {e}"))
                        })?;
                }
            }
        }
        let db = redb::Database::create(path)
            .map_err(|e| GuardStoreError::Io(format!("open guard store: {e}")))?;
        // Enforce owner-only file permissions on the store file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| GuardStoreError::Io(format!("set guard store perms: {e}")))?;
        }
        let store = Self {
            db,
            path: path.to_path_buf(),
        };
        store.ensure_schema()?;
        Ok(store)
    }

    /// Return the store path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Initialize or verify the schema version in the meta table.
    fn ensure_schema(&self) -> Result<(), GuardStoreError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| GuardStoreError::Io(format!("begin write: {e}")))?;
        {
            let mut meta = txn
                .open_table(META_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("open meta table: {e}")))?;
            let found_version: Option<u32> = meta
                .get("schema_version")
                .map_err(|e| GuardStoreError::Io(format!("read schema_version: {e}")))?
                .map(|guard| {
                    let bytes: &[u8] = guard.value();
                    u32::from_le_bytes(bytes.try_into().unwrap_or([0, 0, 0, 0]))
                });
            match found_version {
                Some(version) => {
                    check_schema_version(version)?;
                }
                None => {
                    // First open: write schema version.
                    let version_bytes = GUARD_SCHEMA_VERSION.to_le_bytes();
                    meta.insert("schema_version", version_bytes.as_slice())
                        .map_err(|e| GuardStoreError::Io(format!("write schema_version: {e}")))?;
                }
            }
        }
        // Create all tables so they exist for reads even before first write.
        {
            let _ = txn
                .open_table(ROOTS_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("create roots table: {e}")))?;
            let _ = txn
                .open_table(ATTESTATIONS_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("create attestations table: {e}")))?;
            let _ = txn
                .open_table(ROOT_GAPS_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("create root_gaps table: {e}")))?;
            let _ = txn
                .open_table(SERVICE_STATE_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("create service_state table: {e}")))?;
        }
        txn.commit()
            .map_err(|e| GuardStoreError::Io(format!("commit schema: {e}")))?;
        Ok(())
    }

    /// Load all root records from the durable store into a registry.
    pub fn load_roots(&self) -> Result<RootRegistry, GuardStoreError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| GuardStoreError::Io(format!("begin read: {e}")))?;
        let table = txn
            .open_table(ROOTS_TABLE)
            .map_err(|e| GuardStoreError::Io(format!("open roots table: {e}")))?;
        let mut registry = RootRegistry::new();
        for entry in table
            .range::<&[u8]>(..)
            .map_err(|e| GuardStoreError::Io(format!("iterate roots: {e}")))?
        {
            let (key, value) =
                entry.map_err(|e| GuardStoreError::Io(format!("read root entry: {e}")))?;
            let record: GuardRootRecord =
                serde_json::from_slice(value.value()).map_err(|e| GuardStoreError::Corrupt {
                    detail: format!("deserialize root record: {e}"),
                })?;
            registry.roots.insert(key.value().to_vec(), record);
        }
        Ok(registry)
    }

    /// Save a single root record to the durable store.
    pub fn save_root(&self, record: &GuardRootRecord) -> Result<(), GuardStoreError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| GuardStoreError::Io(format!("begin write: {e}")))?;
        {
            let mut table = txn
                .open_table(ROOTS_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("open roots table: {e}")))?;
            let value = serde_json::to_vec(record)
                .map_err(|e| GuardStoreError::Io(format!("serialize root record: {e}")))?;
            table
                .insert(record.canonical_path.as_slice(), value.as_slice())
                .map_err(|e| GuardStoreError::Io(format!("insert root: {e}")))?;
        }
        txn.commit()
            .map_err(|e| GuardStoreError::Io(format!("commit root: {e}")))?;
        Ok(())
    }

    /// Remove a root record from the durable store.
    pub fn remove_root(&self, canonical_path: &[u8]) -> Result<(), GuardStoreError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| GuardStoreError::Io(format!("begin write: {e}")))?;
        {
            let mut table = txn
                .open_table(ROOTS_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("open roots table: {e}")))?;
            table
                .remove(canonical_path)
                .map_err(|e| GuardStoreError::Io(format!("remove root: {e}")))?;
        }
        txn.commit()
            .map_err(|e| GuardStoreError::Io(format!("commit remove root: {e}")))?;
        Ok(())
    }

    /// Load all clean attestations from the durable store.
    pub fn load_attestations(&self) -> Result<Vec<GitCleanAttestation>, GuardStoreError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| GuardStoreError::Io(format!("begin read: {e}")))?;
        let table = txn
            .open_table(ATTESTATIONS_TABLE)
            .map_err(|e| GuardStoreError::Io(format!("open attestations table: {e}")))?;
        let mut attestations = Vec::new();
        for entry in table
            .range::<&[u8]>(..)
            .map_err(|e| GuardStoreError::Io(format!("iterate attestations: {e}")))?
        {
            let (_, value) =
                entry.map_err(|e| GuardStoreError::Io(format!("read attestation entry: {e}")))?;
            let att: GitCleanAttestation =
                serde_json::from_slice(value.value()).map_err(|e| GuardStoreError::Corrupt {
                    detail: format!("deserialize attestation: {e}"),
                })?;
            attestations.push(att);
        }
        Ok(attestations)
    }

    /// Save a clean attestation to the durable store.
    pub fn save_attestation(&self, att: &GitCleanAttestation) -> Result<(), GuardStoreError> {
        let key = attestation_key(att);
        let txn = self
            .db
            .begin_write()
            .map_err(|e| GuardStoreError::Io(format!("begin write: {e}")))?;
        {
            let mut table = txn
                .open_table(ATTESTATIONS_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("open attestations table: {e}")))?;
            let value = serde_json::to_vec(att)
                .map_err(|e| GuardStoreError::Io(format!("serialize attestation: {e}")))?;
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(|e| GuardStoreError::Io(format!("insert attestation: {e}")))?;
        }
        txn.commit()
            .map_err(|e| GuardStoreError::Io(format!("commit attestation: {e}")))?;
        Ok(())
    }

    /// Remove a clean attestation from the durable store.
    pub fn remove_attestation(&self, att: &GitCleanAttestation) -> Result<(), GuardStoreError> {
        let key = attestation_key(att);
        let txn = self
            .db
            .begin_write()
            .map_err(|e| GuardStoreError::Io(format!("begin write: {e}")))?;
        {
            let mut table = txn
                .open_table(ATTESTATIONS_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("open attestations table: {e}")))?;
            table
                .remove(key.as_slice())
                .map_err(|e| GuardStoreError::Io(format!("remove attestation: {e}")))?;
        }
        txn.commit()
            .map_err(|e| GuardStoreError::Io(format!("commit remove attestation: {e}")))?;
        Ok(())
    }

    /// Remove all attestations for a given detector digest.
    pub fn clear_attestations_for_policy(
        &self,
        policy_short: &str,
    ) -> Result<usize, GuardStoreError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| GuardStoreError::Io(format!("begin write: {e}")))?;
        let removed = {
            let mut table = txn
                .open_table(ATTESTATIONS_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("open attestations table: {e}")))?;
            let prefix = policy_short.as_bytes();
            let mut count = 0usize;
            let keys_to_remove: Vec<Vec<u8>> = table
                .range::<&[u8]>(..)
                .map_err(|e| GuardStoreError::Io(format!("iterate attestations: {e}")))?
                .filter_map(|entry| {
                    let (key, _) = entry.ok()?;
                    let k = key.value();
                    // Key format: hash_algo_label || blob_oid || policy_short
                    // Check if the key ends with the policy prefix.
                    if k.ends_with(prefix) {
                        Some(k.to_vec())
                    } else {
                        None
                    }
                })
                .collect();
            for key in keys_to_remove {
                table
                    .remove(key.as_slice())
                    .map_err(|e| GuardStoreError::Io(format!("remove attestation: {e}")))?;
                count += 1;
            }
            count
        };
        txn.commit()
            .map_err(|e| GuardStoreError::Io(format!("commit clear attestations: {e}")))?;
        Ok(removed)
    }

    /// Save a coverage gap for a root. The key is
    /// canonical_path || 0x00 || blob_oid.
    pub fn save_root_gap(
        &self,
        canonical_path: &[u8],
        blob_oid: &str,
        description: &str,
    ) -> Result<(), GuardStoreError> {
        let mut key = Vec::with_capacity(canonical_path.len() + 1 + blob_oid.len());
        key.extend_from_slice(canonical_path);
        key.push(0);
        key.extend_from_slice(blob_oid.as_bytes());
        let txn = self
            .db
            .begin_write()
            .map_err(|e| GuardStoreError::Io(format!("begin write: {e}")))?;
        {
            let mut table = txn
                .open_table(ROOT_GAPS_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("open root_gaps table: {e}")))?;
            table
                .insert(key.as_slice(), description.as_bytes())
                .map_err(|e| GuardStoreError::Io(format!("insert root gap: {e}")))?;
        }
        txn.commit()
            .map_err(|e| GuardStoreError::Io(format!("commit root gap: {e}")))?;
        Ok(())
    }

    /// Load all coverage gaps for a root.
    pub fn load_root_gaps(
        &self,
        canonical_path: &[u8],
    ) -> Result<Vec<(String, String)>, GuardStoreError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| GuardStoreError::Io(format!("begin read: {e}")))?;
        let table = txn
            .open_table(ROOT_GAPS_TABLE)
            .map_err(|e| GuardStoreError::Io(format!("open root_gaps table: {e}")))?;
        let prefix = canonical_path;
        let mut gaps = Vec::new();
        for entry in table
            .range::<&[u8]>(..)
            .map_err(|e| GuardStoreError::Io(format!("iterate root_gaps: {e}")))?
        {
            let (key, value) =
                entry.map_err(|e| GuardStoreError::Io(format!("read root gap entry: {e}")))?;
            let k = key.value();
            if !k.starts_with(prefix) {
                continue;
            }
            // Verify the null separator follows the prefix to avoid
            // matching a root whose path is a prefix of another
            // (e.g. /repo vs /repo/sub).
            if k.len() <= prefix.len() || k[prefix.len()] != 0 {
                continue;
            }
            // Extract blob_oid after the null separator.
            let rest = &k[prefix.len() + 1..];
            let blob_oid = String::from_utf8_lossy(rest).to_string();
            let desc = String::from_utf8_lossy(value.value()).to_string();
            gaps.push((blob_oid, desc));
        }
        Ok(gaps)
    }

    /// Remove all coverage gaps for a root.
    pub fn clear_root_gaps(&self, canonical_path: &[u8]) -> Result<usize, GuardStoreError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| GuardStoreError::Io(format!("begin write: {e}")))?;
        let removed = {
            let mut table = txn
                .open_table(ROOT_GAPS_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("open root_gaps table: {e}")))?;
            let prefix = canonical_path;
            let keys_to_remove: Vec<Vec<u8>> = table
                .range::<&[u8]>(..)
                .map_err(|e| GuardStoreError::Io(format!("iterate root_gaps: {e}")))?
                .filter_map(|entry| {
                    let (key, _) = entry.ok()?;
                    let k = key.value();
                    if k.starts_with(prefix) && k.len() > prefix.len() && k[prefix.len()] == 0 {
                        Some(k.to_vec())
                    } else {
                        None
                    }
                })
                .collect();
            let count = keys_to_remove.len();
            for key in keys_to_remove {
                table
                    .remove(key.as_slice())
                    .map_err(|e| GuardStoreError::Io(format!("remove root gap: {e}")))?;
            }
            count
        };
        txn.commit()
            .map_err(|e| GuardStoreError::Io(format!("commit clear root gaps: {e}")))?;
        Ok(removed)
    }

    /// Mark the service state as unclean (startup). This is set before
    /// the daemon begins serving requests and cleared after all state
    /// is flushed during a clean shutdown.
    pub fn mark_unclean_shutdown(&self) -> Result<(), GuardStoreError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| GuardStoreError::Io(format!("begin write: {e}")))?;
        {
            let mut table = txn
                .open_table(SERVICE_STATE_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("open service_state table: {e}")))?;
            table
                .insert("clean_shutdown", 0u8)
                .map_err(|e| GuardStoreError::Io(format!("write clean_shutdown: {e}")))?;
        }
        txn.commit()
            .map_err(|e| GuardStoreError::Io(format!("commit service state: {e}")))?;
        Ok(())
    }

    /// Mark the service state as clean (graceful shutdown). Called after
    /// all root records and attestations have been flushed.
    pub fn mark_clean_shutdown(&self) -> Result<(), GuardStoreError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| GuardStoreError::Io(format!("begin write: {e}")))?;
        {
            let mut table = txn
                .open_table(SERVICE_STATE_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("open service_state table: {e}")))?;
            table
                .insert("clean_shutdown", 1u8)
                .map_err(|e| GuardStoreError::Io(format!("write clean_shutdown: {e}")))?;
        }
        txn.commit()
            .map_err(|e| GuardStoreError::Io(format!("commit service state: {e}")))?;
        Ok(())
    }

    /// Check whether the last shutdown was clean.
    /// Returns `true` if the clean_shutdown marker is set to 1,
    /// `false` if it is 0 or absent (treat absent as unclean).
    pub fn was_clean_shutdown(&self) -> Result<bool, GuardStoreError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| GuardStoreError::Io(format!("begin read: {e}")))?;
        let table = txn
            .open_table(SERVICE_STATE_TABLE)
            .map_err(|e| GuardStoreError::Io(format!("open service_state table: {e}")))?;
        let value = table
            .get("clean_shutdown")
            .map_err(|e| GuardStoreError::Io(format!("read clean_shutdown: {e}")))?;
        Ok(value.map(|v| v.value() == 1u8).unwrap_or(false))
    }

    /// Atomically save a root record and its coverage gaps in one
    /// transaction. This ensures the root state and gap records are
    /// consistent across crashes.
    pub fn save_root_with_gaps(
        &self,
        record: &GuardRootRecord,
        gaps: &[(String, String)],
    ) -> Result<(), GuardStoreError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| GuardStoreError::Io(format!("begin write: {e}")))?;
        {
            let mut roots = txn
                .open_table(ROOTS_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("open roots table: {e}")))?;
            let value = serde_json::to_vec(record)
                .map_err(|e| GuardStoreError::Io(format!("serialize root record: {e}")))?;
            roots
                .insert(record.canonical_path.as_slice(), value.as_slice())
                .map_err(|e| GuardStoreError::Io(format!("insert root: {e}")))?;

            // Clear old gaps for this root, then insert new ones.
            let mut gaps_table = txn
                .open_table(ROOT_GAPS_TABLE)
                .map_err(|e| GuardStoreError::Io(format!("open root_gaps table: {e}")))?;
            let prefix = record.canonical_path.as_slice();
            let keys_to_remove: Vec<Vec<u8>> = gaps_table
                .range::<&[u8]>(..)
                .map_err(|e| GuardStoreError::Io(format!("iterate root_gaps: {e}")))?
                .filter_map(|entry| {
                    let (key, _) = entry.ok()?;
                    let k = key.value();
                    if k.starts_with(prefix) && k.len() > prefix.len() && k[prefix.len()] == 0 {
                        Some(k.to_vec())
                    } else {
                        None
                    }
                })
                .collect();
            for key in keys_to_remove {
                gaps_table
                    .remove(key.as_slice())
                    .map_err(|e| GuardStoreError::Io(format!("remove old root gap: {e}")))?;
            }
            for (blob_oid, desc) in gaps {
                let mut key = Vec::with_capacity(prefix.len() + 1 + blob_oid.len());
                key.extend_from_slice(prefix);
                key.push(0);
                key.extend_from_slice(blob_oid.as_bytes());
                gaps_table
                    .insert(key.as_slice(), desc.as_bytes())
                    .map_err(|e| GuardStoreError::Io(format!("insert root gap: {e}")))?;
            }
        }
        txn.commit()
            .map_err(|e| GuardStoreError::Io(format!("commit root with gaps: {e}")))?;
        Ok(())
    }
}

/// Build the durable key for a clean attestation:
/// hash_algorithm_label || 0x00 || blob_oid_hex || 0x00 || detector_digest
fn attestation_key(att: &GitCleanAttestation) -> Vec<u8> {
    let label = match att.hash_algorithm {
        GitHashAlgorithm::Sha1 => "sha1",
        GitHashAlgorithm::Sha256 => "sha256",
    };
    let mut key = Vec::with_capacity(label.len() + 1 + att.blob_oid.len() + 1 + 64);
    key.extend_from_slice(label.as_bytes());
    key.push(0);
    key.extend_from_slice(att.blob_oid.as_bytes());
    key.push(0);
    key.extend_from_slice(att.policy_identity.detector_digest.as_bytes());
    key
}
