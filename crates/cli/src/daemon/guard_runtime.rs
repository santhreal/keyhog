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
    GitCleanAttestation, GitHashAlgorithm, GuardPolicyIdentity, GuardRootMode,
    GuardRootRecord, GuardRootState, GuardTransition, FilesystemIdentity,
};
use keyhog_core::guard_store::{HotAttestationIndex, RootRegistry};
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
    /// Coverage gaps count.
    pub coverage_gaps: u64,
    /// Objects skipped (deletions, symlinks, submodules).
    pub objects_skipped: u64,
    /// When the transaction started.
    pub started_at: Instant,
    /// Policy identity short digest used for attestation lookup.
    pub policy_short_digest: String,
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
        self.dirty_during_indexing.lock().insert(canonical_path.to_vec());
    }

    /// Check and clear the dirty-during-indexing flag for a root.
    /// Returns true if events were observed during indexing.
    pub fn take_dirty_during_indexing(&self, canonical_path: &[u8]) -> bool {
        self.dirty_during_indexing.lock().remove(canonical_path)
    }

    /// Apply a transition to a root. Returns the new state or an error.
    pub fn transition_root(
        &self,
        canonical_path: &[u8],
        event: &GuardTransition,
    ) -> Result<GuardRootState, keyhog_core::guard_state::TransitionError> {
        let mut roots = self.roots.write();
        let record = roots
            .get_mut(canonical_path)
            .ok_or_else(|| keyhog_core::guard_state::TransitionError::Illegal {
                event: event.clone(),
                from: GuardRootState::Stopped,
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

    /// Get a reference to an in-flight transaction.
    pub fn get_transaction(&self, id: u64) -> Option<GuardTransaction> {
        self.transactions.lock().get(&id).map(|t| GuardTransaction {
            transaction_id: t.transaction_id,
            repo_path: t.repo_path.clone(),
            index_fingerprint: t.index_fingerprint.clone(),
            hash_algorithm: t.hash_algorithm,
            clean_hits: t.clean_hits.clone(),
            required_blob_oids: t.required_blob_oids.clone(),
            scanned_oids: t.scanned_oids.clone(),
            bytes_scanned: t.bytes_scanned,
            bytes_requested: t.bytes_requested,
            bytes_hit: t.bytes_hit,
            findings_count: t.findings_count,
            coverage_gaps: t.coverage_gaps,
            objects_skipped: t.objects_skipped,
            started_at: t.started_at,
            policy_short_digest: t.policy_short_digest.clone(),
        })
    }

    /// Record a scanned blob result in a transaction.
    pub fn record_scanned_blob(
        &self,
        txn_id: u64,
        oid: &str,
        bytes: u64,
        findings: u64,
    ) -> Result<(), String> {
        let mut txns = self.transactions.lock();
        let txn = txns
            .get_mut(&txn_id)
            .ok_or_else(|| format!("transaction {} not found", txn_id))?;
        if !txn.required_blob_oids.contains(&oid.to_string()) {
            return Err(format!(
                "transaction {}: blob {} was not in the required set",
                txn_id, oid
            ));
        }
        if txn.scanned_oids.contains(&oid.to_string()) {
            return Err(format!(
                "transaction {}: blob {} already scanned",
                txn_id, oid
            ));
        }
        txn.scanned_oids.push(oid.to_string());
        txn.bytes_scanned += bytes;
        txn.findings_count += findings;
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
        if !txn.required_blob_oids.contains(&oid.to_string()) {
            return Err(format!(
                "transaction {}: blob {} was not in the required set",
                txn_id, oid
            ));
        }
        if txn.scanned_oids.contains(&oid.to_string()) {
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
    /// Finish a transaction and return its final state. Removes it
    /// from the in-flight map.
    pub fn finish_transaction(&self, txn_id: u64) -> Option<GuardTransaction> {
        self.transactions.lock().remove(&txn_id)
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
            tracing::warn!("daemon: guard transaction {} abandoned (timed out after {}s)", id, TRANSACTION_TIMEOUT_SECS);
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
        let record = roots
            .get_mut(canonical_path)
            .ok_or_else(|| format!("root not registered: {}", String::from_utf8_lossy(canonical_path)))?;
        // A commit transaction is an authoritative proof of content
        // state, not a state-machine event. The receipt's
        // terminal_state is the proven state, so set it directly
        // rather than going through the transition table (which
        // would reject EventsClean from Current, for example).
        record.state = receipt.terminal_state;
        record.terminal_sequence = record.terminal_sequence.saturating_add(1);
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
}

impl Default for GuardRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> GuardPolicyIdentity {
        GuardPolicyIdentity {
            build_identity: "abc".to_string(),
            detector_digest: "def".to_string(),
            suppression_digest: String::new(),
            keyhogignore_digest: String::new(),
            config_digest: "ghi".to_string(),
            decode_policy_version: 1,
            source_policy_digest: "jkl".to_string(),
            guard_schema_version: 1,
            report_semantics_version: 1,
        }
    }

    fn test_fs_identity() -> FilesystemIdentity {
        FilesystemIdentity {
            device: 1,
            inode: 2,
        }
    }

    #[test]
    fn runtime_starts_empty() {
        let rt = GuardRuntime::new();
        assert!(rt.is_empty());
        assert_eq!(rt.root_count(), 0);
    }

    #[test]
    fn add_root_creates_stopped_record() {
        let rt = GuardRuntime::new();
        let record = rt
            .add_root(b"/work/project".to_vec(), test_fs_identity(), GuardRootMode::Repo)
            .unwrap();
        assert_eq!(record.state, GuardRootState::Stopped);
        assert_eq!(rt.root_count(), 1);
    }

    #[test]
    fn add_duplicate_root_fails() {
        let rt = GuardRuntime::new();
        rt.add_root(b"/work/project".to_vec(), test_fs_identity(), GuardRootMode::Repo)
            .unwrap();
        let result = rt.add_root(b"/work/project".to_vec(), test_fs_identity(), GuardRootMode::Repo);
        assert!(result.is_err());
    }

    #[test]
    fn remove_root_works() {
        let rt = GuardRuntime::new();
        rt.add_root(b"/work/project".to_vec(), test_fs_identity(), GuardRootMode::Repo)
            .unwrap();
        assert_eq!(rt.root_count(), 1);

        let removed = rt.remove_root(b"/work/project");
        assert!(removed.is_some());
        assert!(rt.is_empty());
    }

    #[test]
    fn transition_root_stopped_to_indexing() {
        let rt = GuardRuntime::new();
        rt.add_root(b"/work/project".to_vec(), test_fs_identity(), GuardRootMode::Repo)
            .unwrap();

        let new_state = rt
            .transition_root(b"/work/project", &GuardTransition::ReconciliationStarted)
            .unwrap();
        assert_eq!(new_state, GuardRootState::Indexing);
    }

    #[test]
    fn transition_root_indexing_to_current() {
        let rt = GuardRuntime::new();
        rt.add_root(b"/work/project".to_vec(), test_fs_identity(), GuardRootMode::Repo)
            .unwrap();
        rt.transition_root(b"/work/project", &GuardTransition::ReconciliationStarted)
            .unwrap();
        let new_state = rt
            .transition_root(b"/work/project", &GuardTransition::ReconciliationClean)
            .unwrap();
        assert_eq!(new_state, GuardRootState::Current);
    }

    #[test]
    fn transition_illegal_returns_error() {
        let rt = GuardRuntime::new();
        rt.add_root(b"/work/project".to_vec(), test_fs_identity(), GuardRootMode::Repo)
            .unwrap();
        let result = rt.transition_root(b"/work/project", &GuardTransition::EventAccepted);
        assert!(result.is_err());
    }

    #[test]
    fn policy_identity_change_transitions_roots_to_stale() {
        let rt = GuardRuntime::new();
        rt.set_policy_identity(test_identity());
        rt.add_root(b"/work/project".to_vec(), test_fs_identity(), GuardRootMode::Repo)
            .unwrap();
        rt.transition_root(b"/work/project", &GuardTransition::ReconciliationStarted)
            .unwrap();
        rt.transition_root(b"/work/project", &GuardTransition::ReconciliationClean)
            .unwrap();
        assert_eq!(
            rt.root_state(b"/work/project"),
            Some(GuardRootState::Current)
        );

        // Change the policy identity.
        let mut new_id = test_identity();
        new_id.detector_digest = "changed".to_string();
        rt.set_policy_identity(new_id);

        assert_eq!(
            rt.root_state(b"/work/project"),
            Some(GuardRootState::StalePolicy)
        );
    }

    #[test]
    fn transaction_ids_are_unique() {
        let rt = GuardRuntime::new();
        let id1 = rt.next_transaction_id();
        let id2 = rt.next_transaction_id();
        let id3 = rt.next_transaction_id();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn count_by_state() {
        let rt = GuardRuntime::new();
        rt.add_root(b"/a".to_vec(), test_fs_identity(), GuardRootMode::Repo)
            .unwrap();
        rt.add_root(b"/b".to_vec(), test_fs_identity(), GuardRootMode::Repo)
            .unwrap();

        assert_eq!(rt.count_by_state(GuardRootState::Stopped), 2);
        assert_eq!(rt.count_by_state(GuardRootState::Current), 0);

        rt.transition_root(b"/a", &GuardTransition::ReconciliationStarted)
            .unwrap();
        rt.transition_root(b"/a", &GuardTransition::ReconciliationClean)
            .unwrap();
        assert_eq!(rt.count_by_state(GuardRootState::Stopped), 1);
        assert_eq!(rt.count_by_state(GuardRootState::Current), 1);
    }

    #[test]
    fn list_roots_returns_all() {
        let rt = GuardRuntime::new();
        rt.add_root(b"/a".to_vec(), test_fs_identity(), GuardRootMode::Repo)
            .unwrap();
        rt.add_root(b"/b".to_vec(), test_fs_identity(), GuardRootMode::Filesystem)
            .unwrap();

        let list = rt.list_roots();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn scanner_residency_is_resident_after_activity() {
        let rt = GuardRuntime::new();
        rt.add_root(b"/work/project".to_vec(), test_fs_identity(), GuardRootMode::Repo)
            .unwrap();
        // add_root calls touch_activity, so residency should be "resident".
        assert_eq!(rt.scanner_residency(), "resident");
    }

    #[test]
    fn scanner_residency_is_active_during_transaction() {
        let rt = GuardRuntime::new();
        rt.add_root(b"/work/project".to_vec(), test_fs_identity(), GuardRootMode::Repo)
            .unwrap();
        let txn = GuardTransaction {
            transaction_id: rt.next_transaction_id(),
            repo_path: "/work/project".to_string(),
            index_fingerprint: "abc".to_string(),
            hash_algorithm: GitHashAlgorithm::Sha1,
            clean_hits: Vec::new(),
            required_blob_oids: vec!["oid1".to_string()],
            scanned_oids: Vec::new(),
            bytes_scanned: 0,
            bytes_requested: 0,
            bytes_hit: 0,
            findings_count: 0,
            coverage_gaps: 0,
            objects_skipped: 0,
            started_at: Instant::now(),
            policy_short_digest: "abc".to_string(),
        };
        rt.begin_transaction(txn);
        assert_eq!(rt.scanner_residency(), "active");
        rt.finish_transaction(1);
        assert_eq!(rt.scanner_residency(), "resident");
    }

    #[test]
    fn touch_activity_updates_residency() {
        let rt = GuardRuntime::new();
        // New runtime was just created, so it should be "resident".
        assert_eq!(rt.scanner_residency(), "resident");
        // touch_activity is called by all guard operations.
        rt.touch_activity();
        assert_eq!(rt.scanner_residency(), "resident");
    }

    #[test]
    fn scanner_residency_uses_configured_timeout() {
        let rt = GuardRuntime::new();
        // Set a very short timeout (0 seconds) so it immediately reports idle.
        rt.set_scanner_idle_timeout(0);
        // Touch activity to reset the clock, then check.
        rt.touch_activity();
        // With 0 second timeout, even immediate check should be idle-unload
        // because elapsed (>= 0) is not < 0.
        assert_eq!(rt.scanner_residency(), "idle-unload");
    }

    #[test]
    fn scanner_residency_respects_large_timeout() {
        let rt = GuardRuntime::new();
        // Set a very large timeout so it always reports resident.
        rt.set_scanner_idle_timeout(999_999);
        assert_eq!(rt.scanner_residency(), "resident");
    }

    #[test]
    fn restore_root_preserves_metadata_but_resets_state() {
        let rt = GuardRuntime::new();
        let record = keyhog_core::guard_state::GuardRootRecord {
            canonical_path: b"/restored/repo".to_vec(),
            filesystem_identity: test_fs_identity(),
            mode: GuardRootMode::Repo,
            state: keyhog_core::guard_state::GuardRootState::Current,
            terminal_sequence: 42,
            accepted_event_sequence: 10,
            completed_event_sequence: 8,
            initial_reconciliation_time: Some(1000),
            last_reconciliation_time: Some(2000),
            backend_route_label: "scalar-cpu".to_string(),
            last_receipt: None,
        };
        rt.restore_root(record.clone()).expect("restore root");

        // The restored root should be in the registry.
        let loaded = rt.root_record(b"/restored/repo").expect("root exists");
        // Metadata should be preserved.
        assert_eq!(loaded.canonical_path, record.canonical_path);
        assert_eq!(loaded.filesystem_identity, record.filesystem_identity);
        assert_eq!(loaded.mode, record.mode);
        assert_eq!(loaded.terminal_sequence, record.terminal_sequence);
        // The restore_root method itself preserves state; the caller
        // (server.rs) is responsible for resetting to Stopped.
        assert_eq!(loaded.state, keyhog_core::guard_state::GuardRootState::Current);
    }

    #[test]
    fn restore_root_rejects_duplicate() {
        let rt = GuardRuntime::new();
        let record = keyhog_core::guard_state::GuardRootRecord {
            canonical_path: b"/dup/repo".to_vec(),
            filesystem_identity: test_fs_identity(),
            mode: GuardRootMode::Repo,
            state: keyhog_core::guard_state::GuardRootState::Stopped,
            terminal_sequence: 0,
            accepted_event_sequence: 0,
            completed_event_sequence: 0,
            initial_reconciliation_time: None,
            last_reconciliation_time: None,
            backend_route_label: String::new(),
            last_receipt: None,
        };
        rt.restore_root(record.clone()).expect("first restore");
        let result = rt.restore_root(record);
        assert!(result.is_err(), "duplicate restore should fail");
    }

    #[test]
    fn restore_root_then_reconcile_transitions_to_indexing() {
        let rt = GuardRuntime::new();
        // Simulate a restart: restore a root as Stopped.
        let record = keyhog_core::guard_state::GuardRootRecord {
            canonical_path: b"/restart/repo".to_vec(),
            filesystem_identity: test_fs_identity(),
            mode: GuardRootMode::Repo,
            state: keyhog_core::guard_state::GuardRootState::Stopped,
            terminal_sequence: 5,
            accepted_event_sequence: 0,
            completed_event_sequence: 0,
            initial_reconciliation_time: None,
            last_reconciliation_time: None,
            backend_route_label: String::new(),
            last_receipt: None,
        };
        rt.restore_root(record).expect("restore");

        // A stopped root should be able to transition to Indexing
        // via the normal reconcile flow.
        let transition = GuardTransition::ReconciliationStarted;
        let result = rt.transition_root(b"/restart/repo", &transition);
        assert!(result.is_ok(), "stopped root should transition to indexing");
        assert_eq!(
            rt.root_state(b"/restart/repo"),
            Some(keyhog_core::guard_state::GuardRootState::Indexing)
        );
    }
}
