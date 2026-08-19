//! Guard runtime: root registry, state transitions, attestation lookup, and
//! commit transaction tracking.
//!
//! This module holds the live guard state inside the daemon process. It
//! owns:
//! - the root registry (which roots are registered, their states)
//! - the hot attestation index (clean blob cache)
//! - guard state transitions (applying events to root states)
//! - in-flight commit transactions (Begin -> Plan -> Blob* -> Finish)
//!
//! It does NOT own watcher registration or durable persistence. Those are
//! wired in later lanes. This module is the in-process state the daemon's
//! dispatch function talks to when a guard request arrives.

use keyhog_core::guard_state::{
    FilesystemIdentity, GitCleanAttestation, GitHashAlgorithm, GuardPolicyIdentity, GuardRootMode,
    GuardRootRecord, GuardRootState, GuardTransition,
};
use keyhog_core::guard_store::{HotAttestationIndex, RootRegistry};
use keyhog_core::RawMatch;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::time::Instant;

/// One in-flight guard commit transaction.
pub struct GuardTransaction {
    /// Server-assigned transaction ID.
    pub transaction_id: u64,
    /// Repository path (canonical, from the client).
    pub repo_path: String,
    /// Index fingerprint captured at Begin time.
    pub index_fingerprint: String,
    /// Git hash algorithm.
    pub hash_algorithm: GitHashAlgorithm,
    /// Object OIDs that were clean hits (no payload needed).
    pub clean_hits: Vec<String>,
    /// Object OIDs that need payload streaming and scanning.
    pub required_blob_oids: Vec<String>,
    /// OIDs received and scanned so far.
    pub scanned_oids: Vec<String>,
    /// Bytes scanned so far.
    pub bytes_scanned: u64,
    /// Total bytes requested (sum of all object sizes in the plan).
    pub bytes_requested: u64,
    /// Bytes hit in the clean attestation cache (no payload scanned).
    pub bytes_hit: u64,
    /// Findings count across all scanned blobs.
    pub findings_count: u64,
    /// Findings that block the default evidence policy.
    pub blocking_findings_count: u64,
    /// Exact finalized findings retained for the terminal protected receipt.
    pub reported_findings: Vec<RawMatch>,
    /// Coverage gaps count.
    pub coverage_gaps: u64,
    /// Objects skipped (deletions, symlinks, submodules).
    pub objects_skipped: u64,
    /// When the transaction started.
    pub started_at: Instant,
    /// Policy identity bound to this transaction.
    pub policy_identity: GuardPolicyIdentity,
    /// Staged source paths grouped by object OID.
    pub source_paths_by_oid: HashMap<String, Vec<String>>,
}

/// Minimal owned context needed to scan one streamed blob.
pub struct GuardBlobContext {
    pub repo_path: String,
    pub hash_algorithm: GitHashAlgorithm,
    pub policy_identity: GuardPolicyIdentity,
    pub source_paths: Vec<String>,
}

/// Minimal snapshot needed to validate a finish request without cloning the
/// transaction's path index or accounting vectors.
pub struct GuardFinishContext {
    pub repo_path: String,
    pub index_fingerprint: String,
    pub required_blob_count: u64,
    pub scanned_blob_count: u64,
}

/// Live guard runtime state held by the daemon.
pub struct GuardRuntime {
    /// Root registry: canonical path bytes -> root record.
    roots: RwLock<RootRegistry>,
    /// Hot clean attestation index (memory-bounded LRU).
    attestations: HotAttestationIndex,
    /// Current policy identity (updated when the daemon's scanner/config
    /// identity changes).
    current_identity: RwLock<Option<GuardPolicyIdentity>>,
    /// Transaction ID counter for guard commit transactions.
    next_transaction_id: Mutex<u64>,
    /// In-flight transactions: transaction_id -> transaction state.
    transactions: Mutex<HashMap<u64, GuardTransaction>>,
    /// Last time any guard activity occurred (commit, event, root change).
    last_activity: Mutex<Instant>,
    /// Configured scanner idle timeout in seconds before the residency
    /// label reports "idle-unload". Defaults to 300 (5 minutes).
    scanner_idle_timeout_secs: Mutex<u64>,
    /// Roots that received filesystem events while in the Indexing
    /// state. The baseline reconciliation handler checks this after
    /// the scan completes and transitions such roots to Dirty
    /// instead of Current, so changes during the walk are not lost.
    dirty_during_indexing: parking_lot::Mutex<std::collections::HashSet<Vec<u8>>>,
    /// Roots that observed watcher overflow (lost events) while Indexing.
    /// Baseline completion must end Degraded rather than Current/Dirty.
    coverage_lost_during_indexing: parking_lot::Mutex<std::collections::HashSet<Vec<u8>>>,
    /// Named reason if the watcher backend disconnected.
    watcher_disconnection_reason: parking_lot::RwLock<Option<String>>,
    /// Explicit watcher status description ("watching", "unmonitored", "disconnected: ...", etc.).
    watcher_status: parking_lot::RwLock<Option<String>>,
}

/// Default scanner idle timeout in seconds (5 minutes).
const DEFAULT_SCANNER_IDLE_TIMEOUT_SECS: u64 = 300;

/// Maximum age of an in-flight transaction before it is swept as
/// abandoned. A client that disconnects mid-transaction leaves it
/// behind; this reclaims the memory and unblocks the residency label.
const TRANSACTION_TIMEOUT_SECS: u64 = 600;

impl GuardRuntime {
    /// Create a new empty guard runtime.
    pub fn new() -> Self {
        Self {
            roots: RwLock::new(RootRegistry::new()),
            attestations: HotAttestationIndex::new(),
            current_identity: RwLock::new(None),
            next_transaction_id: Mutex::new(1),
            transactions: Mutex::new(HashMap::new()),
            last_activity: Mutex::new(Instant::now()),
            scanner_idle_timeout_secs: Mutex::new(DEFAULT_SCANNER_IDLE_TIMEOUT_SECS),
            dirty_during_indexing: parking_lot::Mutex::new(std::collections::HashSet::new()),
            coverage_lost_during_indexing: parking_lot::Mutex::new(std::collections::HashSet::new()),
            watcher_disconnection_reason: parking_lot::RwLock::new(None),
            watcher_status: parking_lot::RwLock::new(None),
        }
    }

    /// Create with a custom hot index memory budget.
    pub fn with_hot_index_budget(budget: usize) -> Self {
        Self {
            roots: RwLock::new(RootRegistry::new()),
            attestations: HotAttestationIndex::with_budget(budget),
            current_identity: RwLock::new(None),
            next_transaction_id: Mutex::new(1),
            transactions: Mutex::new(HashMap::new()),
            last_activity: Mutex::new(Instant::now()),
            scanner_idle_timeout_secs: Mutex::new(DEFAULT_SCANNER_IDLE_TIMEOUT_SECS),
            dirty_during_indexing: parking_lot::Mutex::new(std::collections::HashSet::new()),
            coverage_lost_during_indexing: parking_lot::Mutex::new(std::collections::HashSet::new()),
            watcher_disconnection_reason: parking_lot::RwLock::new(None),
            watcher_status: parking_lot::RwLock::new(None),
        }
    }

    /// Set the scanner idle timeout in seconds. After this many seconds
    /// of guard inactivity, the residency label reports "idle-unload".
    pub fn set_scanner_idle_timeout(&self, secs: u64) {
        *self.scanner_idle_timeout_secs.lock() = secs;
    }

    /// Set the current policy identity. When it changes, all existing
    /// attestations are invalidated and roots transition to stale-policy.
    pub fn set_policy_identity(&self, identity: GuardPolicyIdentity) {
        let mut current = self.current_identity.write();
        if let Some(ref existing) = *current {
            if !existing.is_compatible_with(&identity) {
                // Invalidate all stale attestations.
                self.attestations.invalidate_for_policy(&identity);
                // Transition active roots to stale-policy through the
                // state machine. Degraded roots stay degraded: their
                // coverage loss must not be masked by a lesser label.
                let mut roots = self.roots.write();
                let paths: Vec<Vec<u8>> = roots
                    .list()
                    .iter()
                    .filter(|r| r.state != GuardRootState::Stopped)
                    .map(|r| r.canonical_path.clone())
                    .collect();
                for path in paths {
                    if let Some(r) = roots.get_mut(&path) {
                        match r.state.transition(&GuardTransition::PolicyChanged) {
                            Ok(new_state) => {
                                r.state = new_state;
                                r.terminal_sequence = r.terminal_sequence.saturating_add(1);
                            }
                            Err(_) => {
                                // Transition is illegal (e.g. Degraded).
                                // Leave the root in its current state.
                            }
                        }
                    }
                }
            }
        }
        *current = Some(identity);
    }

    /// Register a new root. Returns the initial record in Stopped state.
    pub fn add_root(
        &self,
        canonical_path: Vec<u8>,
        filesystem_identity: FilesystemIdentity,
        mode: GuardRootMode,
    ) -> Result<GuardRootRecord, String> {
        let mut roots = self.roots.write();
        if roots.get(&canonical_path).is_some() {
            return Err(format!(
                "root already registered: {}",
                String::from_utf8_lossy(&canonical_path)
            ));
        }
        let record = roots.register(canonical_path, filesystem_identity, mode);
        self.touch_activity();
        Ok(record)
    }

    /// Restore a root record from the durable store. Unlike `add_root`,
    /// this preserves the full record state (state, sequences, timestamps).
    /// Used during daemon startup to reload persisted roots.
    pub fn restore_root(&self, record: GuardRootRecord) -> Result<(), String> {
        let mut roots = self.roots.write();
        let key = record.canonical_path.clone();
        if roots.get(&key).is_some() {
            return Err(format!(
                "root already registered: {}",
                String::from_utf8_lossy(&key)
            ));
        }
        roots.insert_record(record);
        self.touch_activity();
        Ok(())
    }

    /// Remove a root from the registry.
    pub fn remove_root(&self, canonical_path: &[u8]) -> Option<GuardRootRecord> {
        let removed = self.roots.write().remove(canonical_path);
        if removed.is_some() {
            self.dirty_during_indexing.lock().remove(canonical_path);
            self.coverage_lost_during_indexing
                .lock()
                .remove(canonical_path);
            self.touch_activity();
        }
        removed
    }

    /// Get the current state of a root.
    pub fn root_state(&self, canonical_path: &[u8]) -> Option<GuardRootState> {
        self.roots.read().get(canonical_path).map(|r| r.state)
    }

    /// Get a copy of a root record.
    pub fn root_record(&self, canonical_path: &[u8]) -> Option<GuardRootRecord> {
        self.roots.read().get(canonical_path).cloned()
    }

    /// Mark that a root received filesystem events while in the
    /// Indexing state. The baseline handler checks this after the
    /// scan completes.
    pub fn mark_dirty_during_indexing(&self, canonical_path: &[u8]) {
        self.dirty_during_indexing
            .lock()
            .insert(canonical_path.to_vec());
    }

    /// Check and clear the dirty-during-indexing flag for a root.
    /// Returns true if events were observed during indexing.
    pub fn take_dirty_during_indexing(&self, canonical_path: &[u8]) -> bool {
        self.dirty_during_indexing.lock().remove(canonical_path)
    }

    /// Mark that watcher overflow lost events while this root was Indexing.
    pub fn mark_coverage_lost_during_indexing(&self, canonical_path: &[u8]) {
        self.coverage_lost_during_indexing
            .lock()
            .insert(canonical_path.to_vec());
    }

    /// Check and clear the coverage-lost-during-indexing flag.
    pub fn take_coverage_lost_during_indexing(&self, canonical_path: &[u8]) -> bool {
        self.coverage_lost_during_indexing
            .lock()
            .remove(canonical_path)
    }

    /// Apply a transition to a root. Returns the new state or an error.
    pub fn transition_root(
        &self,
        canonical_path: &[u8],
        event: &GuardTransition,
    ) -> Result<GuardRootState, keyhog_core::guard_state::TransitionError> {
        let mut roots = self.roots.write();
        let record = roots.get_mut(canonical_path).ok_or_else(|| {
            keyhog_core::guard_state::TransitionError::Illegal {
                event: event.clone(),
                from: GuardRootState::Stopped,
            }
        })?;
        let new_state = record.state.transition(event)?;
        record.state = new_state;
        if let GuardTransition::ReconciliationClean
        | GuardTransition::ReconciliationFindings
        | GuardTransition::ReconciliationDegraded
        | GuardTransition::EventsClean
        | GuardTransition::EventsFindings
        | GuardTransition::EventsDegraded = event
        {
            record.terminal_sequence = record.terminal_sequence.saturating_add(1);
        }
        self.touch_activity();
        Ok(new_state)
    }

    /// Look up a clean attestation. A hit does not read blob payload.
    pub fn lookup_attestation(
        &self,
        hash_algorithm: GitHashAlgorithm,
        blob_oid: &str,
        policy_short_digest: &str,
    ) -> Option<GitCleanAttestation> {
        self.attestations
            .get(hash_algorithm, blob_oid, policy_short_digest)
    }

    /// Insert a clean attestation. Only complete clean outcomes.
    pub fn insert_attestation(&self, attestation: GitCleanAttestation) {
        self.attestations.insert(attestation);
    }

    /// Allocate a new transaction ID.
    pub fn next_transaction_id(&self) -> u64 {
        let mut counter = self.next_transaction_id.lock();
        let id = *counter;
        *counter += 1;
        id
    }

    /// Start a new commit transaction. Returns the transaction ID.
    pub fn begin_transaction(&self, txn: GuardTransaction) -> u64 {
        let id = txn.transaction_id;
        self.transactions.lock().insert(id, txn);
        self.touch_activity();
        id
    }

    /// Return the bounded context for one required blob without cloning the
    /// transaction's complete staged-path index.
    pub fn blob_context(&self, id: u64, oid: &str) -> Result<GuardBlobContext, String> {
        let txns = self.transactions.lock();
        let txn = txns
            .get(&id)
            .ok_or_else(|| format!("transaction {} not found", id))?;
        if !txn
            .required_blob_oids
            .iter()
            .any(|required| required == oid)
        {
            return Err(format!(
                "transaction {}: blob {} was not in the required set",
                id, oid
            ));
        }
        if txn.scanned_oids.iter().any(|scanned| scanned == oid) {
            return Err(format!("transaction {}: blob {} already scanned", id, oid));
        }
        let source_paths = txn.source_paths_by_oid.get(oid).cloned().ok_or_else(|| {
            format!(
                "transaction {}: blob {} has no staged source paths",
                id, oid
            )
        })?;
        Ok(GuardBlobContext {
            repo_path: txn.repo_path.clone(),
            hash_algorithm: txn.hash_algorithm,
            policy_identity: txn.policy_identity.clone(),
            source_paths,
        })
    }

    /// Snapshot only the fields required to validate a finish request.
    pub fn finish_context(&self, id: u64) -> Option<GuardFinishContext> {
        self.transactions
            .lock()
            .get(&id)
            .map(|txn| GuardFinishContext {
                repo_path: txn.repo_path.clone(),
                index_fingerprint: txn.index_fingerprint.clone(),
                required_blob_count: txn.required_blob_oids.len() as u64,
                scanned_blob_count: txn.scanned_oids.len() as u64,
            })
    }

    /// Record a scanned blob result in a transaction.
    pub fn record_scanned_blob(
        &self,
        txn_id: u64,
        oid: &str,
        bytes: u64,
        reported_findings: Vec<RawMatch>,
        blocking_findings: u64,
    ) -> Result<(), String> {
        let findings = reported_findings.len() as u64;
        if blocking_findings > findings {
            return Err(format!(
                "transaction {}: default-policy blocking findings {} exceed total {}",
                txn_id, blocking_findings, findings
            ));
        }
        let mut txns = self.transactions.lock();
        let txn = txns
            .get_mut(&txn_id)
            .ok_or_else(|| format!("transaction {} not found", txn_id))?;
        if !txn
            .required_blob_oids
            .iter()
            .any(|required| required == oid)
        {
            return Err(format!(
                "transaction {}: blob {} was not in the required set",
                txn_id, oid
            ));
        }
        if txn.scanned_oids.iter().any(|scanned| scanned == oid) {
            return Err(format!(
                "transaction {}: blob {} already scanned",
                txn_id, oid
            ));
        }
        txn.scanned_oids.push(oid.to_string());
        txn.bytes_scanned += bytes;
        txn.findings_count += findings;
        txn.blocking_findings_count += blocking_findings;
        txn.reported_findings.extend(reported_findings);
        self.touch_activity();
        Ok(())
    }

    /// Record a coverage gap for a blob that could not be scanned.
    /// The blob is counted as scanned (so conservation holds) but
    /// increments coverage_gaps, forcing the terminal state to
    /// Degraded rather than Current.
    pub fn record_coverage_gap(&self, txn_id: u64, oid: &str, bytes: u64) -> Result<(), String> {
        let mut txns = self.transactions.lock();
        let txn = txns
            .get_mut(&txn_id)
            .ok_or_else(|| format!("transaction {} not found", txn_id))?;
        if !txn
            .required_blob_oids
            .iter()
            .any(|required| required == oid)
        {
            return Err(format!(
                "transaction {}: blob {} was not in the required set",
                txn_id, oid
            ));
        }
        if txn.scanned_oids.iter().any(|scanned| scanned == oid) {
            return Err(format!(
                "transaction {}: blob {} already scanned",
                txn_id, oid
            ));
        }
        txn.scanned_oids.push(oid.to_string());
        txn.bytes_scanned += bytes;
        txn.coverage_gaps += 1;
        self.touch_activity();
        Ok(())
    }
    /// Finish a transaction only after the caller validates its terminal wire
    /// representation. A failed validation leaves the transaction available
    /// for a corrected finish request.
    pub fn finish_transaction_if<F>(
        &self,
        txn_id: u64,
        validate: F,
    ) -> Result<Option<GuardTransaction>, String>
    where
        F: FnOnce(&GuardTransaction) -> Result<(), String>,
    {
        let mut transactions = self.transactions.lock();
        let Some(transaction) = transactions.get(&txn_id) else {
            return Ok(None);
        };
        validate(transaction)?;
        Ok(transactions.remove(&txn_id))
    }

    /// Remove transactions older than `TRANSACTION_TIMEOUT_SECS`.
    /// Called periodically from the watcher loop to reclaim memory
    /// from clients that disconnected mid-transaction.
    pub fn sweep_stale_transactions(&self) {
        let now = Instant::now();
        let timeout = std::time::Duration::from_secs(TRANSACTION_TIMEOUT_SECS);
        let mut txns = self.transactions.lock();
        let stale_ids: Vec<u64> = txns
            .iter()
            .filter(|(_, txn)| now.duration_since(txn.started_at) > timeout)
            .map(|(id, _)| *id)
            .collect();
        for id in &stale_ids {
            txns.remove(id);
            tracing::warn!(
                "daemon: guard transaction {} abandoned (timed out after {}s)",
                id,
                TRANSACTION_TIMEOUT_SECS
            );
        }
    }

    /// Number of in-flight transactions.
    pub fn active_transaction_count(&self) -> usize {
        self.transactions.lock().len()
    }

    /// Get the current policy identity, if set.
    pub fn policy_identity(&self) -> Option<GuardPolicyIdentity> {
        self.current_identity.read().clone()
    }

    /// Autoroute evidence status label for status display.
    /// Returns "established" when a policy identity is set, "pending"
    /// otherwise. The daemon does not hold autoroute calibration state;
    /// the label reflects whether the scanner is ready to serve guard
    /// transactions.
    pub fn autoroute_evidence_status(&self) -> &'static str {
        if self.current_identity.read().is_some() {
            "established"
        } else {
            "pending"
        }
    }

    /// Update a root's last receipt and terminal sequence after a
    /// commit transaction completes. Also transitions the root state
    /// based on the transaction outcome.
    pub fn update_root_after_commit(
        &self,
        canonical_path: &[u8],
        receipt: keyhog_core::guard_state::GuardReceipt,
    ) -> Result<(), String> {
        let mut roots = self.roots.write();
        let record = roots.get_mut(canonical_path).ok_or_else(|| {
            format!(
                "root not registered: {}",
                String::from_utf8_lossy(canonical_path)
            )
        })?;
        // A commit transaction is an authoritative proof of content
        // state, not a state-machine event. The receipt's
        // terminal_state is the proven state, so set it directly
        // rather than going through the transition table (which
        // would reject EventsClean from Current, for example).
        record.state = receipt.terminal_state;
        record.terminal_sequence = record.terminal_sequence.saturating_add(1);
        let mut receipt = receipt;
        receipt.terminal_sequence = record.terminal_sequence;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if record.initial_reconciliation_time.is_none() {
            record.initial_reconciliation_time = Some(now);
        }
        record.last_reconciliation_time = Some(now);
        record.last_receipt = Some(receipt);
        Ok(())
    }

    /// Number of registered roots.
    pub fn root_count(&self) -> usize {
        self.roots.read().len()
    }

    /// Count roots by state.
    pub fn count_by_state(&self, state: GuardRootState) -> usize {
        self.roots.read().count_by_state(state)
    }

    /// List all root records.
    pub fn list_roots(&self) -> Vec<GuardRootRecord> {
        self.roots.read().list().into_iter().cloned().collect()
    }

    /// Whether the guard runtime has any registered roots.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.roots.read().is_empty()
    }

    /// Record that guard activity occurred. Called on every guard
    /// operation (commit transaction, event processing, root change).
    pub fn touch_activity(&self) {
        *self.last_activity.lock() = Instant::now();
    }

    /// Scanner residency label for GuardStatus. The scanner is always
    /// in memory in the daemon process; this label reports whether the
    /// guard is actively using it or has been idle past the unload
    /// threshold.
    ///
    /// - "active": in-flight commit transactions right now
    /// - "resident": recent guard activity within the idle threshold
    /// - "idle-unload": no guard activity for longer than the threshold
    pub fn scanner_residency(&self) -> &'static str {
        if !self.transactions.lock().is_empty() {
            return "active";
        }
        let elapsed = self.last_activity.lock().elapsed();
        let timeout = *self.scanner_idle_timeout_secs.lock();
        if elapsed.as_secs() < timeout {
            "resident"
        } else {
            "idle-unload"
        }
    }

    /// Record that the watcher backend disconnected with a named reason.
    pub fn record_watcher_disconnection(&self, reason: impl Into<String>) {
        let reason_str = reason.into();
        *self.watcher_disconnection_reason.write() = Some(reason_str.clone());
        *self.watcher_status.write() = Some(format!("disconnected: {}", reason_str));
    }

    /// Reason why the watcher backend disconnected, if any.
    pub fn watcher_disconnection_reason(&self) -> Option<String> {
        self.watcher_disconnection_reason.read().clone()
    }

    /// Whether the watcher backend is disconnected.
    pub fn is_watcher_disconnected(&self) -> bool {
        self.watcher_disconnection_reason.read().is_some()
    }

    /// Set the explicit watcher status label/description.
    pub fn set_watcher_status(&self, status: impl Into<String>) {
        *self.watcher_status.write() = Some(status.into());
    }

    /// Get the watcher status label/description.
    pub fn watcher_status(&self) -> Option<String> {
        self.watcher_status.read().clone()
    }
}

impl Default for GuardRuntime {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
#[path = "../../tests/unit/daemon_guard_runtime.rs"]
mod tests;
