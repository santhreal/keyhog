//! Guard runtime: root registry, state transitions, and attestation lookup.
//!
//! This module holds the live guard state inside the daemon process. It
//! owns:
//! - the root registry (which roots are registered, their states)
//! - the hot attestation index (clean blob cache)
//! - guard state transitions (applying events to root states)
//!
//! It does NOT own scanner execution, watcher registration, or durable
//! persistence. Those are wired in later lanes. This module is the
//! in-process state the daemon's dispatch function talks to when a guard
//! request arrives.

use keyhog_core::guard_state::{
    GitCleanAttestation, GitHashAlgorithm, GuardPolicyIdentity, GuardRootMode,
    GuardRootRecord, GuardRootState, GuardTransition, FilesystemIdentity,
};
use keyhog_core::guard_store::{HotAttestationIndex, RootRegistry};
use parking_lot::{Mutex, RwLock};

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
}

impl GuardRuntime {
    /// Create a new empty guard runtime.
    pub fn new() -> Self {
        Self {
            roots: RwLock::new(RootRegistry::new()),
            attestations: HotAttestationIndex::new(),
            current_identity: RwLock::new(None),
            next_transaction_id: parking_lot::Mutex::new(1),
        }
    }

    /// Create with a custom hot index memory budget.
    pub fn with_hot_index_budget(budget: usize) -> Self {
        Self {
            roots: RwLock::new(RootRegistry::new()),
            attestations: HotAttestationIndex::with_budget(budget),
            current_identity: RwLock::new(None),
            next_transaction_id: parking_lot::Mutex::new(1),
        }
    }

    /// Set the current policy identity. When it changes, all existing
    /// attestations are invalidated and roots transition to stale-policy.
    pub fn set_policy_identity(&self, identity: GuardPolicyIdentity) {
        let mut current = self.current_identity.write();
        if let Some(ref existing) = *current {
            if !existing.is_compatible_with(&identity) {
                // Invalidate all stale attestations.
                self.attestations.invalidate_for_policy(&identity);
                // Transition all active roots to stale-policy.
                let mut roots = self.roots.write();
                let paths: Vec<Vec<u8>> = roots
                    .list()
                    .iter()
                    .filter(|r| r.state != GuardRootState::Stopped)
                    .map(|r| r.canonical_path.clone())
                    .collect();
                for path in paths {
                    if let Some(r) = roots.get_mut(&path) {
                        r.state = GuardRootState::StalePolicy;
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
        Ok(roots.register(canonical_path, filesystem_identity, mode))
    }

    /// Remove a root from the registry.
    pub fn remove_root(&self, canonical_path: &[u8]) -> Option<GuardRootRecord> {
        self.roots.write().remove(canonical_path)
    }

    /// Get the current state of a root.
    pub fn root_state(&self, canonical_path: &[u8]) -> Option<GuardRootState> {
        self.roots.read().get(canonical_path).map(|r| r.state)
    }

    /// Get a copy of a root record.
    pub fn root_record(&self, canonical_path: &[u8]) -> Option<GuardRootRecord> {
        self.roots.read().get(canonical_path).cloned()
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
}
