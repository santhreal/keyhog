//! Tests for the guard store: hot attestation index, schema versioning,
//! and root registry.

use keyhog_core::guard_state::{
    FilesystemIdentity, GitCleanAttestation, GitHashAlgorithm, GuardPolicyIdentity,
    GuardRootMode, GuardRootState, GUARD_SCHEMA_VERSION,
};
use keyhog_core::guard_store::{
    check_schema_version, DurableGuardStore, GuardStoreError, HotAttestationIndex,
    RootRegistry, DEFAULT_HOT_INDEX_MEMORY,
};

fn sample_identity() -> GuardPolicyIdentity {
    GuardPolicyIdentity {
        build_identity: "abc123".to_string(),
        detector_digest: "deadbeef".to_string(),
        suppression_digest: String::new(),
        keyhogignore_digest: String::new(),
        config_digest: "feedface".to_string(),
        decode_policy_version: 1,
        source_policy_digest: "baadf00d".to_string(),
        guard_schema_version: GUARD_SCHEMA_VERSION,
        report_semantics_version: 1,
    }
}

fn sample_attestation(oid: &str, seq: u64) -> GitCleanAttestation {
    GitCleanAttestation {
        hash_algorithm: GitHashAlgorithm::Sha1,
        blob_oid: oid.to_string(),
        object_size: 1024,
        policy_identity: sample_identity(),
        last_seen_sequence: seq,
    }
}

// ── Hot attestation index ────────────────────────────────────────────────

#[test]
fn hot_index_starts_empty() {
    let index = HotAttestationIndex::new();
    assert!(index.is_empty());
    assert_eq!(index.len(), 0);
}

#[test]
fn hot_index_insert_and_get() {
    let index = HotAttestationIndex::new();
    let att = sample_attestation("abc123", 1);
    index.insert(att.clone());

    let short = sample_identity().short_digest().unwrap();
    let got = index.get(GitHashAlgorithm::Sha1, "abc123", &short);
    assert!(got.is_some());
    assert_eq!(got.unwrap().blob_oid, "abc123");
}

#[test]
fn hot_index_miss_returns_none() {
    let index = HotAttestationIndex::new();
    let short = sample_identity().short_digest().unwrap();
    let got = index.get(GitHashAlgorithm::Sha1, "nonexistent", &short);
    assert!(got.is_none());
}

#[test]
fn hot_index_remove() {
    let index = HotAttestationIndex::new();
    index.insert(sample_attestation("abc123", 1));
    let short = sample_identity().short_digest().unwrap();

    let removed = index.remove(GitHashAlgorithm::Sha1, "abc123", &short);
    assert!(removed.is_some());

    let got = index.get(GitHashAlgorithm::Sha1, "abc123", &short);
    assert!(got.is_none());
}

#[test]
fn hot_index_evicts_lru_when_full() {
    // Small budget to force eviction quickly.
    let index = HotAttestationIndex::with_budget(320);
    // Insert enough entries to fill and evict.
    for i in 0..10 {
        index.insert(sample_attestation(&format!("oid{i}"), i));
    }
    // The first entry should have been evicted (LRU).
    let short = sample_identity().short_digest().unwrap();
    let first = index.get(GitHashAlgorithm::Sha1, "oid0", &short);
    assert!(
        first.is_none(),
        "oldest entry should have been evicted by LRU"
    );
    // The last entry should still be present.
    let last = index.get(GitHashAlgorithm::Sha1, "oid9", &short);
    assert!(last.is_some(), "most recent entry should be present");
}

#[test]
fn hot_index_invalidate_for_policy_removes_stale() {
    let index = HotAttestationIndex::new();
    let id = sample_identity();
    index.insert(sample_attestation("oid1", 1));
    index.insert(sample_attestation("oid2", 2));

    // Change the policy identity.
    let mut new_id = id.clone();
    new_id.detector_digest = "changed".to_string();

    let removed = index.invalidate_for_policy(&new_id);
    assert_eq!(removed, 2, "both entries should be invalidated");
    assert!(index.is_empty());
}

#[test]
fn hot_index_invalidate_keeps_compatible() {
    let index = HotAttestationIndex::new();
    let id = sample_identity();
    index.insert(sample_attestation("oid1", 1));

    let removed = index.invalidate_for_policy(&id);
    assert_eq!(removed, 0, "compatible entries should not be removed");
    assert_eq!(index.len(), 1);
}

#[test]
fn hot_index_clear() {
    let index = HotAttestationIndex::new();
    index.insert(sample_attestation("oid1", 1));
    index.insert(sample_attestation("oid2", 2));
    assert_eq!(index.len(), 2);

    index.clear();
    assert!(index.is_empty());
}

#[test]
fn hot_index_default_budget_is_64mib() {
    let index = HotAttestationIndex::new();
    assert_eq!(index.budget(), DEFAULT_HOT_INDEX_MEMORY);
    assert_eq!(DEFAULT_HOT_INDEX_MEMORY, 64 * 1024 * 1024);
}

#[test]
fn hot_index_different_oid_does_not_collide() {
    let index = HotAttestationIndex::new();
    index.insert(sample_attestation("oid1", 1));
    index.insert(sample_attestation("oid2", 2));

    let short = sample_identity().short_digest().unwrap();
    assert!(index.get(GitHashAlgorithm::Sha1, "oid1", &short).is_some());
    assert!(index.get(GitHashAlgorithm::Sha1, "oid2", &short).is_some());
    assert_eq!(index.len(), 2);
}

#[test]
fn hot_index_different_hash_algorithm_does_not_collide() {
    let index = HotAttestationIndex::new();
    let mut att = sample_attestation("oid1", 1);
    att.hash_algorithm = GitHashAlgorithm::Sha1;
    index.insert(att.clone());

    let mut att2 = sample_attestation("oid1", 2);
    att2.hash_algorithm = GitHashAlgorithm::Sha256;
    index.insert(att2);

    let short = sample_identity().short_digest().unwrap();
    assert!(index.get(GitHashAlgorithm::Sha1, "oid1", &short).is_some());
    assert!(index.get(GitHashAlgorithm::Sha256, "oid1", &short).is_some());
    assert_eq!(index.len(), 2);
}

// ── Schema versioning ────────────────────────────────────────────────────

#[test]
fn schema_version_one_is_accepted() {
    assert!(check_schema_version(1).is_ok());
}

#[test]
fn schema_version_zero_is_obsolete() {
    let result = check_schema_version(0);
    assert!(matches!(result, Err(GuardStoreError::SchemaObsolete { found: 0 })));
}

#[test]
fn schema_version_two_is_too_new() {
    let result = check_schema_version(2);
    assert!(matches!(
        result,
        Err(GuardStoreError::SchemaTooNew {
            found: 2,
            supported: GUARD_SCHEMA_VERSION
        })
    ));
}

// ── Root registry ────────────────────────────────────────────────────────

#[test]
fn root_registry_starts_empty() {
    let registry = RootRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
}

#[test]
fn root_registry_register_creates_stopped_record() {
    let mut registry = RootRegistry::new();
    let path = b"/work/project".to_vec();
    let record = registry.register(
        path.clone(),
        FilesystemIdentity {
            device: 1,
            inode: 2,
        },
        GuardRootMode::Repo,
    );

    assert_eq!(record.canonical_path, path);
    assert_eq!(record.state, GuardRootState::Stopped);
    assert_eq!(record.terminal_sequence, 0);
    assert!(record.last_receipt.is_none());
}

#[test]
fn root_registry_get_by_path() {
    let mut registry = RootRegistry::new();
    let path = b"/work/project".to_vec();
    registry.register(
        path.clone(),
        FilesystemIdentity {
            device: 1,
            inode: 2,
        },
        GuardRootMode::Repo,
    );

    assert!(registry.get(&path).is_some());
    assert!(registry.get(b"/nonexistent").is_none());
}

#[test]
fn root_registry_get_mut_for_state_update() {
    let mut registry = RootRegistry::new();
    let path = b"/work/project".to_vec();
    registry.register(
        path.clone(),
        FilesystemIdentity {
            device: 1,
            inode: 2,
        },
        GuardRootMode::Repo,
    );

    {
        let record = registry.get_mut(&path).unwrap();
        record.state = GuardRootState::Current;
        record.terminal_sequence = 42;
    }

    let record = registry.get(&path).unwrap();
    assert_eq!(record.state, GuardRootState::Current);
    assert_eq!(record.terminal_sequence, 42);
}

#[test]
fn root_registry_remove() {
    let mut registry = RootRegistry::new();
    let path = b"/work/project".to_vec();
    registry.register(
        path.clone(),
        FilesystemIdentity {
            device: 1,
            inode: 2,
        },
        GuardRootMode::Repo,
    );
    assert_eq!(registry.len(), 1);

    let removed = registry.remove(&path);
    assert!(removed.is_some());
    assert!(registry.is_empty());
}

#[test]
fn root_registry_list() {
    let mut registry = RootRegistry::new();
    registry.register(
        b"/a".to_vec(),
        FilesystemIdentity {
            device: 1,
            inode: 1,
        },
        GuardRootMode::Repo,
    );
    registry.register(
        b"/b".to_vec(),
        FilesystemIdentity {
            device: 2,
            inode: 2,
        },
        GuardRootMode::Filesystem,
    );

    let list = registry.list();
    assert_eq!(list.len(), 2);
}

#[test]
fn root_registry_count_by_state() {
    let mut registry = RootRegistry::new();
    registry.register(
        b"/a".to_vec(),
        FilesystemIdentity {
            device: 1,
            inode: 1,
        },
        GuardRootMode::Repo,
    );
    registry.register(
        b"/b".to_vec(),
        FilesystemIdentity {
            device: 2,
            inode: 2,
        },
        GuardRootMode::Repo,
    );

    // Both start as Stopped.
    assert_eq!(registry.count_by_state(GuardRootState::Stopped), 2);
    assert_eq!(registry.count_by_state(GuardRootState::Current), 0);

    // Move one to Current.
    registry.get_mut(b"/a").unwrap().state = GuardRootState::Current;
    assert_eq!(registry.count_by_state(GuardRootState::Stopped), 1);
    assert_eq!(registry.count_by_state(GuardRootState::Current), 1);
}

// ── Durable store ────────────────────────────────────────────────────────

fn temp_store_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("guard.redb");
    (dir, path)
}

#[test]
fn durable_store_opens_and_creates_schema() {
    let (_dir, path) = temp_store_path();
    {
        let store = DurableGuardStore::open(&path).expect("open store");
        assert_eq!(store.path(), &path);
    }
    // Reopening should verify the schema version.
    let _store2 = DurableGuardStore::open(&path).expect("reopen store");
}

#[test]
fn durable_store_save_and_load_root() {
    let (_dir, path) = temp_store_path();
    let store = DurableGuardStore::open(&path).expect("open store");

    let record = keyhog_core::guard_state::GuardRootRecord {
        canonical_path: b"/work/project".to_vec(),
        filesystem_identity: FilesystemIdentity { device: 1, inode: 2 },
        mode: GuardRootMode::Repo,
        state: GuardRootState::Current,
        terminal_sequence: 42,
        accepted_event_sequence: 10,
        completed_event_sequence: 8,
        initial_reconciliation_time: Some(1000),
        last_reconciliation_time: Some(2000),
        backend_route_label: "simd".to_string(),
        last_receipt: None,
    };
    store.save_root(&record).expect("save root");

    let loaded = store.load_roots().expect("load roots");
    assert_eq!(loaded.len(), 1);
    let got = loaded.get(b"/work/project").expect("root exists");
    assert_eq!(got.state, GuardRootState::Current);
    assert_eq!(got.terminal_sequence, 42);
    assert_eq!(got.initial_reconciliation_time, Some(1000));
}

#[test]
fn durable_store_remove_root() {
    let (_dir, path) = temp_store_path();
    let store = DurableGuardStore::open(&path).expect("open store");

    let record = keyhog_core::guard_state::GuardRootRecord {
        canonical_path: b"/work/project".to_vec(),
        filesystem_identity: FilesystemIdentity { device: 1, inode: 2 },
        mode: GuardRootMode::Repo,
        state: GuardRootState::Stopped,
        terminal_sequence: 0,
        accepted_event_sequence: 0,
        completed_event_sequence: 0,
        initial_reconciliation_time: None,
        last_reconciliation_time: None,
        backend_route_label: String::new(),
        last_receipt: None,
    };
    store.save_root(&record).expect("save root");
    assert_eq!(store.load_roots().expect("load").len(), 1);
    store.remove_root(b"/work/project").expect("remove root");
    assert_eq!(store.load_roots().expect("load").len(), 0);
}

#[test]
fn durable_store_save_and_load_attestation() {
    let (_dir, path) = temp_store_path();
    let store = DurableGuardStore::open(&path).expect("open store");

    let att = sample_attestation("abc123", 1);
    store.save_attestation(&att).expect("save attestation");

    let loaded = store.load_attestations().expect("load attestations");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].blob_oid, "abc123");
}

#[test]
fn durable_store_remove_attestation() {
    let (_dir, path) = temp_store_path();
    let store = DurableGuardStore::open(&path).expect("open store");

    let att = sample_attestation("abc123", 1);
    store.save_attestation(&att).expect("save attestation");
    assert_eq!(store.load_attestations().expect("load").len(), 1);
    store.remove_attestation(&att).expect("remove attestation");
    assert_eq!(store.load_attestations().expect("load").len(), 0);
}
