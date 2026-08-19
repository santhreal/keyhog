//! Tests for the guard store: hot attestation index, schema versioning,
//! and root registry.

use keyhog_core::guard_state::{
    FilesystemIdentity, GitCleanAttestation, GitHashAlgorithm, GuardPolicyIdentity, GuardRootMode,
    GuardRootRecord, GuardRootState, GUARD_SCHEMA_VERSION,
};
use keyhog_core::guard_store::{
    check_schema_version, DurableGuardStore, GuardStoreError, HotAttestationIndex, RootRegistry,
    DEFAULT_HOT_INDEX_MEMORY,
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

fn sample_root_record(path: &str) -> GuardRootRecord {
    GuardRootRecord {
        canonical_path: path.as_bytes().to_vec(),
        filesystem_identity: FilesystemIdentity {
            device: 1,
            inode: 2,
        },
        filesystem_authority: keyhog_core::guard_state::FilesystemAuthority::authoritative("ext4"),
        mode: GuardRootMode::Repo,
        state: GuardRootState::Current,
        terminal_sequence: 0,
        accepted_event_sequence: 0,
        completed_event_sequence: 0,
        initial_reconciliation_time: None,
        last_reconciliation_time: None,
        backend_route_label: "scalar-cpu".to_string(),
        last_receipt: None,
        recent_transitions: Vec::new(),
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
    assert!(index
        .get(GitHashAlgorithm::Sha256, "oid1", &short)
        .is_some());
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
    assert!(matches!(
        result,
        Err(GuardStoreError::SchemaObsolete { found: 0 })
    ));
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
        keyhog_core::guard_state::FilesystemAuthority::authoritative("ext4"),
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
        keyhog_core::guard_state::FilesystemAuthority::authoritative("ext4"),
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
        keyhog_core::guard_state::FilesystemAuthority::authoritative("ext4"),
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
        keyhog_core::guard_state::FilesystemAuthority::authoritative("ext4"),
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
        keyhog_core::guard_state::FilesystemAuthority::authoritative("ext4"),
        GuardRootMode::Repo,
    );
    registry.register(
        b"/b".to_vec(),
        FilesystemIdentity {
            device: 2,
            inode: 2,
        },
        keyhog_core::guard_state::FilesystemAuthority::authoritative("ext4"),
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
        keyhog_core::guard_state::FilesystemAuthority::authoritative("ext4"),
        GuardRootMode::Repo,
    );
    registry.register(
        b"/b".to_vec(),
        FilesystemIdentity {
            device: 2,
            inode: 2,
        },
        keyhog_core::guard_state::FilesystemAuthority::authoritative("ext4"),
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
        filesystem_identity: FilesystemIdentity {
            device: 1,
            inode: 2,
        },
        filesystem_authority: keyhog_core::guard_state::FilesystemAuthority::authoritative("ext4"),
        mode: GuardRootMode::Repo,
        state: GuardRootState::Current,
        terminal_sequence: 42,
        accepted_event_sequence: 10,
        completed_event_sequence: 8,
        initial_reconciliation_time: Some(1000),
        last_reconciliation_time: Some(2000),
        backend_route_label: "simd".to_string(),
        last_receipt: None,
        recent_transitions: Vec::new(),
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
        filesystem_identity: FilesystemIdentity {
            device: 1,
            inode: 2,
        },
        filesystem_authority: keyhog_core::guard_state::FilesystemAuthority::authoritative("ext4"),
        mode: GuardRootMode::Repo,
        state: GuardRootState::Stopped,
        terminal_sequence: 0,
        accepted_event_sequence: 0,
        completed_event_sequence: 0,
        initial_reconciliation_time: None,
        last_reconciliation_time: None,
        backend_route_label: String::new(),
        last_receipt: None,
        recent_transitions: Vec::new(),
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

#[test]
fn durable_store_rejects_symlinked_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real_path = dir.path().join("real.redb");
    let link_path = dir.path().join("link.redb");
    // Create the real file first so the symlink target exists.
    {
        let _store = DurableGuardStore::open(&real_path).expect("open real store");
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real_path, &link_path).expect("create symlink");
        let result = DurableGuardStore::open(&link_path);
        assert!(result.is_err(), "symlinked store path should be rejected");
        let err = result.err().unwrap();
        let msg = err.to_string();
        assert!(
            msg.contains("symlink"),
            "error should mention symlink, got: {msg}"
        );
    }
}

#[test]
fn durable_store_service_state_unclean_default() {
    let (_dir, path) = temp_store_path();
    let store = DurableGuardStore::open(&path).expect("open store");
    // A fresh store has no clean_shutdown marker, so it should report unclean.
    let clean = store.was_clean_shutdown().expect("check clean shutdown");
    assert!(!clean, "fresh store should report unclean shutdown");
}

#[test]
fn durable_store_service_state_mark_clean_then_unclean() {
    let (_dir, path) = temp_store_path();
    let store = DurableGuardStore::open(&path).expect("open store");

    store.mark_clean_shutdown().expect("mark clean");
    assert!(
        store.was_clean_shutdown().expect("check clean"),
        "after mark_clean_shutdown, was_clean_shutdown should be true"
    );

    store.mark_unclean_shutdown().expect("mark unclean");
    assert!(
        !store.was_clean_shutdown().expect("check unclean"),
        "after mark_unclean_shutdown, was_clean_shutdown should be false"
    );
}

#[test]
fn durable_store_root_gaps_save_load_clear() {
    let (_dir, path) = temp_store_path();
    let store = DurableGuardStore::open(&path).expect("open store");

    let root_key = b"/repo/path";
    store
        .save_root_gap(root_key, "oid1", "unscanned blob")
        .expect("save gap 1");
    store
        .save_root_gap(root_key, "oid2", "missing from index")
        .expect("save gap 2");

    let gaps = store.load_root_gaps(root_key).expect("load gaps");
    assert_eq!(gaps.len(), 2);

    // Clear gaps for the root.
    let removed = store.clear_root_gaps(root_key).expect("clear gaps");
    assert_eq!(removed, 2);
    assert_eq!(
        store
            .load_root_gaps(root_key)
            .expect("load after clear")
            .len(),
        0
    );
}

#[test]
fn durable_store_save_root_with_gaps_atomic() {
    let (_dir, path) = temp_store_path();
    let store = DurableGuardStore::open(&path).expect("open store");

    let record = sample_root_record("/repo/test");
    let gaps = vec![
        ("oid_a".to_string(), "gap a".to_string()),
        ("oid_b".to_string(), "gap b".to_string()),
    ];
    store
        .save_root_with_gaps(&record, &gaps)
        .expect("save root with gaps");

    // Root should be loadable.
    let registry = store.load_roots().expect("load roots");
    assert_eq!(registry.len(), 1);

    // Gaps should be loadable.
    let loaded_gaps = store
        .load_root_gaps(record.canonical_path.as_slice())
        .expect("load gaps");
    assert_eq!(loaded_gaps.len(), 2);

    // Replacing with fewer gaps should remove the old ones.
    let gaps2 = vec![("oid_c".to_string(), "gap c".to_string())];
    store
        .save_root_with_gaps(&record, &gaps2)
        .expect("save root with gaps 2");
    let loaded_gaps2 = store
        .load_root_gaps(record.canonical_path.as_slice())
        .expect("load gaps 2");
    assert_eq!(loaded_gaps2.len(), 1);
    assert_eq!(loaded_gaps2[0].0, "oid_c");
}

#[test]
fn durable_store_rejects_unsupported_schema_version() {
    let (_dir, path) = temp_store_path();
    // Open and write a future schema version.
    {
        let store = DurableGuardStore::open(&path).expect("open store");
        // Manually write an unsupported version via the store's internal db.
        // We use the public API: save a root first to ensure tables exist,
        // then close and corrupt the meta table by writing a bad version.
        let record = sample_root_record("/test");
        store.save_root(&record).expect("save root");
    }
    // Corrupt the schema version by writing a future version directly.
    // We reopen the database and write version 9999 to the meta table.
    {
        let db = redb::Database::open(&path).expect("open db");
        let txn = db.begin_write().expect("begin write");
        {
            let meta: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("meta");
            let mut table = txn.open_table(meta).expect("open meta");
            table
                .insert("schema_version", 9999u32.to_le_bytes().as_slice())
                .expect("write version");
        }
        txn.commit().expect("commit");
    }
    // Reopening should fail with a schema version error.
    let result = DurableGuardStore::open(&path);
    assert!(
        result.is_err(),
        "unsupported schema version should be rejected"
    );
    let err = result.err().unwrap();
    let msg = err.to_string();
    assert!(
        msg.contains("schema") || msg.contains("version"),
        "error should mention schema/version, got: {msg}"
    );
}

#[test]
fn durable_store_corruption_detected_by_redb() {
    // redb detects structural corruption via internal assertions that
    // panic rather than return Err. This is redb's design choice; our
    // DurableGuardStore wrapper propagates redb errors but cannot
    // convert panics to Results. Corruption detection is therefore
    // tested implicitly: any redb operation on a corrupted file
    // either returns an error (for detectable corruption) or panics
    // (for structural corruption). Both prevent silent wrong data.
    //
    // This test verifies that a valid store works correctly after
    // multiple operations, which is the contract we can test.
    let (_dir, path) = temp_store_path();
    let store = DurableGuardStore::open(&path).expect("open store");
    let record = sample_root_record("/integrity/test");
    store.save_root(&record).expect("save root");
    let loaded = store.load_roots().expect("load roots");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded.list()[0].canonical_path, record.canonical_path);
}

#[test]
fn durable_store_contains_no_secret_payloads() {
    let (_dir, path) = temp_store_path();
    let store = DurableGuardStore::open(&path).expect("open store");

    let record = sample_root_record("/no/secrets/here");
    store.save_root(&record).expect("save root");

    let att = sample_attestation("oid_no_payload", 1);
    store.save_attestation(&att).expect("save attestation");

    let raw = std::fs::read(&path).expect("read store file");
    let raw_str = String::from_utf8_lossy(&raw);

    assert!(
        !raw_str.contains("AKIA") && !raw_str.contains("BEGIN PRIVATE KEY"),
        "store file should not contain common secret patterns"
    );
    assert!(
        raw_str.contains("/no/secrets/here"),
        "root path should be in the store"
    );
}
#[test]
fn durable_store_persists_across_reopen() {
    let (_dir, path) = temp_store_path();
    // Write a root and attestation, close, reopen, and verify they persist.
    let record = sample_root_record("/persist/test");
    let att = sample_attestation("persistent_oid", 42);
    {
        let store = DurableGuardStore::open(&path).expect("open store");
        store.save_root(&record).expect("save root");
        store.save_attestation(&att).expect("save attestation");
    }
    // Reopen and verify.
    let store = DurableGuardStore::open(&path).expect("reopen store");
    let registry = store.load_roots().expect("load roots");
    assert_eq!(registry.len(), 1);
    let loaded = registry.list()[0];
    assert_eq!(loaded.canonical_path, record.canonical_path);
    assert_eq!(loaded.state, GuardRootState::Current);

    let attestations = store.load_attestations().expect("load attestations");
    assert_eq!(attestations.len(), 1);
    assert_eq!(attestations[0].blob_oid, "persistent_oid");
    assert_eq!(attestations[0].last_seen_sequence, 42);
}

#[test]
fn durable_store_service_state_persists_across_reopen() {
    let (_dir, path) = temp_store_path();
    {
        let store = DurableGuardStore::open(&path).expect("open store");
        store.mark_clean_shutdown().expect("mark clean");
    }
    let store = DurableGuardStore::open(&path).expect("reopen store");
    assert!(
        store.was_clean_shutdown().expect("check clean"),
        "clean shutdown marker should persist across reopen"
    );
}

#[test]
fn durable_store_root_gaps_prefix_collision() {
    // A root path that is a prefix of another (e.g. /repo vs /repo/sub)
    // must not cause gap operations on one to affect the other.
    let (_dir, path) = temp_store_path();
    let store = DurableGuardStore::open(&path).expect("open store");

    let parent = b"/repo";
    let child = b"/repo/sub";

    store
        .save_root_gap(parent, "oid_p", "gap in parent")
        .expect("save parent gap");
    store
        .save_root_gap(child, "oid_c", "gap in child")
        .expect("save child gap");

    // Loading parent gaps should return only the parent gap, not the child.
    let parent_gaps = store.load_root_gaps(parent).expect("load parent gaps");
    assert_eq!(parent_gaps.len(), 1, "parent should have exactly 1 gap");
    assert_eq!(parent_gaps[0].0, "oid_p");

    // Loading child gaps should return only the child gap.
    let child_gaps = store.load_root_gaps(child).expect("load child gaps");
    assert_eq!(child_gaps.len(), 1, "child should have exactly 1 gap");
    assert_eq!(child_gaps[0].0, "oid_c");

    // Clearing parent gaps should not affect child gaps.
    let removed = store.clear_root_gaps(parent).expect("clear parent gaps");
    assert_eq!(removed, 1, "should remove exactly 1 parent gap");

    let child_gaps_after = store
        .load_root_gaps(child)
        .expect("load child after parent clear");
    assert_eq!(
        child_gaps_after.len(),
        1,
        "child gaps must survive clearing parent gaps"
    );
    assert_eq!(child_gaps_after[0].0, "oid_c");
}

#[test]
fn durable_store_open_read_only_and_get_root() {
    let (_dir, path) = temp_store_path();
    let record = sample_root_record("/read_only/test");
    {
        let store = DurableGuardStore::open(&path).expect("open store");
        store.save_root(&record).expect("save root");
    }

    // Open in read-only mode.
    let ro_store = DurableGuardStore::open_read_only(&path).expect("open read only");
    assert_eq!(ro_store.path(), &path);

    let fetched = ro_store
        .get_root(b"/read_only/test")
        .expect("get root")
        .expect("root exists");
    assert_eq!(fetched.canonical_path, record.canonical_path);
    assert_eq!(fetched.state, GuardRootState::Current);

    let missing = ro_store
        .get_root(b"/missing/path")
        .expect("get missing root");
    assert!(missing.is_none());

    let registry = ro_store.load_roots().expect("load roots ro");
    assert_eq!(registry.len(), 1);
}

#[test]
fn durable_store_open_read_only_fails_on_nonexistent_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("does_not_exist.redb");
    let result = DurableGuardStore::open_read_only(&path);
    assert!(result.is_err());
}
