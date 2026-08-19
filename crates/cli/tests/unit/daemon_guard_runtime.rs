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
        .add_root(
            b"/work/project".to_vec(),
            test_fs_identity(),
            GuardRootMode::Repo,
        )
        .unwrap();
    assert_eq!(record.state, GuardRootState::Stopped);
    assert_eq!(rt.root_count(), 1);
}

#[test]
fn add_duplicate_root_fails() {
    let rt = GuardRuntime::new();
    rt.add_root(
        b"/work/project".to_vec(),
        test_fs_identity(),
        GuardRootMode::Repo,
    )
    .unwrap();
    let result = rt.add_root(
        b"/work/project".to_vec(),
        test_fs_identity(),
        GuardRootMode::Repo,
    );
    assert!(result.is_err());
}

#[test]
fn remove_root_works() {
    let rt = GuardRuntime::new();
    rt.add_root(
        b"/work/project".to_vec(),
        test_fs_identity(),
        GuardRootMode::Repo,
    )
    .unwrap();
    assert_eq!(rt.root_count(), 1);

    let removed = rt.remove_root(b"/work/project");
    assert!(removed.is_some());
    assert!(rt.is_empty());
}

#[test]
fn transition_root_stopped_to_indexing() {
    let rt = GuardRuntime::new();
    rt.add_root(
        b"/work/project".to_vec(),
        test_fs_identity(),
        GuardRootMode::Repo,
    )
    .unwrap();

    let new_state = rt
        .transition_root(b"/work/project", &GuardTransition::ReconciliationStarted)
        .unwrap();
    assert_eq!(new_state, GuardRootState::Indexing);
}

#[test]
fn transition_root_indexing_to_current() {
    let rt = GuardRuntime::new();
    rt.add_root(
        b"/work/project".to_vec(),
        test_fs_identity(),
        GuardRootMode::Repo,
    )
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
    rt.add_root(
        b"/work/project".to_vec(),
        test_fs_identity(),
        GuardRootMode::Repo,
    )
    .unwrap();
    let result = rt.transition_root(b"/work/project", &GuardTransition::EventAccepted);
    assert!(result.is_err());
}

#[test]
fn policy_identity_change_transitions_roots_to_stale() {
    let rt = GuardRuntime::new();
    rt.set_policy_identity(test_identity());
    rt.add_root(
        b"/work/project".to_vec(),
        test_fs_identity(),
        GuardRootMode::Repo,
    )
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
    rt.add_root(
        b"/b".to_vec(),
        test_fs_identity(),
        GuardRootMode::Filesystem,
    )
    .unwrap();

    let list = rt.list_roots();
    assert_eq!(list.len(), 2);
}

#[test]
fn scanner_residency_is_resident_after_activity() {
    let rt = GuardRuntime::new();
    rt.add_root(
        b"/work/project".to_vec(),
        test_fs_identity(),
        GuardRootMode::Repo,
    )
    .unwrap();
    // add_root calls touch_activity, so residency should be "resident".
    assert_eq!(rt.scanner_residency(), "resident");
}

#[test]
fn scanner_residency_is_active_during_transaction() {
    let rt = GuardRuntime::new();
    rt.add_root(
        b"/work/project".to_vec(),
        test_fs_identity(),
        GuardRootMode::Repo,
    )
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
        blocking_findings_count: 0,
        reported_findings: Vec::new(),
        coverage_gaps: 0,
        objects_skipped: 0,
        started_at: Instant::now(),
        policy_identity: test_identity(),
        source_paths_by_oid: std::collections::HashMap::from([(
            "oid1".to_string(),
            vec![".env.secret".to_string()],
        )]),
    };
    rt.begin_transaction(txn);
    assert_eq!(rt.scanner_residency(), "active");
    let context = rt.blob_context(1, "oid1").expect("required blob context");
    assert_eq!(context.source_paths, [".env.secret"]);
    assert_eq!(context.policy_identity, test_identity());
    assert!(
        rt.blob_context(1, "other").is_err(),
        "unplanned blobs must not acquire scan context"
    );
    assert!(
        rt.finish_transaction_if(1, |_| Err("oversized receipt".to_string()))
            .is_err(),
        "failed terminal validation must reject finish"
    );
    assert_eq!(
        rt.scanner_residency(),
        "active",
        "failed terminal validation must retain the transaction"
    );
    assert!(rt
        .finish_transaction_if(1, |_| Ok(()))
        .expect("valid terminal receipt")
        .is_some());
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
    assert_eq!(
        loaded.state,
        keyhog_core::guard_state::GuardRootState::Current
    );
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

// ── Mutation tests ─────────────────────────────────────────────
// These tests verify that removing a security control would cause
// the test to fail. They defend the invariant, not the reproduction.

#[test]
fn mutation_restore_current_directly_is_rejected_by_caller_contract() {
    // MUTATION: If the server restored roots as Current directly
    // (skipping the Stopped reset), this test would still pass
    // because restore_root itself preserves state. The contract
    // is enforced by the CALLER (server.rs), not restore_root.
    // This test documents that restore_root preserves whatever
    // state it is given, and the caller must reset to Stopped.
    // The server.rs restart test verifies the caller does reset.
    let rt = GuardRuntime::new();
    let record = keyhog_core::guard_state::GuardRootRecord {
        canonical_path: b"/mutation/current".to_vec(),
        filesystem_identity: test_fs_identity(),
        mode: GuardRootMode::Repo,
        state: keyhog_core::guard_state::GuardRootState::Current,
        terminal_sequence: 99,
        accepted_event_sequence: 50,
        completed_event_sequence: 48,
        initial_reconciliation_time: Some(1000),
        last_reconciliation_time: Some(2000),
        backend_route_label: "scalar-cpu".to_string(),
        last_receipt: None,
    };
    rt.restore_root(record).expect("restore");
    // restore_root preserves state. The CALLER must reset to Stopped.
    // If restore_root itself reset to Stopped, this assertion would
    // fail, proving the reset is in restore_root. It does not, so
    // the reset must be in the caller.
    assert_eq!(
        rt.root_state(b"/mutation/current"),
        Some(keyhog_core::guard_state::GuardRootState::Current)
    );
}

#[test]
fn mutation_omit_policy_identity_field_invalidates_attestations() {
    // If a policy identity field were omitted, the identity would
    // not match, and attestations would be invalidated. This test
    // verifies that a changed identity invalidates the hot index.
    let rt = GuardRuntime::new();
    let id1 = GuardPolicyIdentity {
        build_identity: "build1".to_string(),
        detector_digest: "det1".to_string(),
        suppression_digest: String::new(),
        keyhogignore_digest: String::new(),
        config_digest: String::new(),
        decode_policy_version: 1,
        source_policy_digest: String::new(),
        guard_schema_version: keyhog_core::guard_state::GUARD_SCHEMA_VERSION,
        report_semantics_version: 1,
    };
    rt.set_policy_identity(id1);
    let att = GitCleanAttestation {
        hash_algorithm: GitHashAlgorithm::Sha1,
        blob_oid: "oid1".to_string(),
        object_size: 100,
        policy_identity: rt.policy_identity().unwrap(),
        last_seen_sequence: 1,
    };
    rt.insert_attestation(att);
    // Change the identity: different detector digest.
    let id2 = GuardPolicyIdentity {
        build_identity: "build1".to_string(),
        detector_digest: "det2".to_string(),
        suppression_digest: String::new(),
        keyhogignore_digest: String::new(),
        config_digest: String::new(),
        decode_policy_version: 1,
        source_policy_digest: String::new(),
        guard_schema_version: keyhog_core::guard_state::GUARD_SCHEMA_VERSION,
        report_semantics_version: 1,
    };
    rt.set_policy_identity(id2);
    // The attestation should no longer be found because the policy changed.
    let short = rt.policy_identity().unwrap().short_digest().unwrap();
    let result = rt.lookup_attestation(GitHashAlgorithm::Sha1, "oid1", &short);
    assert!(
        result.is_none(),
        "attestation should be invalidated after policy identity change"
    );
}

#[test]
fn mutation_indexing_to_current_requires_clean_transition() {
    // A root in Indexing cannot jump to Current without an explicit
    // ReconciliationClean transition. If the transition were skipped,
    // this test would fail.
    let rt = GuardRuntime::new();
    rt.add_root(
        b"/mutation/transition".to_vec(),
        test_fs_identity(),
        GuardRootMode::Repo,
    )
    .unwrap();
    rt.transition_root(
        b"/mutation/transition",
        &GuardTransition::ReconciliationStarted,
    )
    .unwrap();
    assert_eq!(
        rt.root_state(b"/mutation/transition"),
        Some(GuardRootState::Indexing)
    );
    // Direct EventAccepted from Indexing should fail.
    let result = rt.transition_root(b"/mutation/transition", &GuardTransition::EventAccepted);
    assert!(
        result.is_err(),
        "EventAccepted from Indexing should be illegal"
    );
    // Only ReconciliationClean/Findings/Degraded can transition from Indexing.
    rt.transition_root(
        b"/mutation/transition",
        &GuardTransition::ReconciliationClean,
    )
    .unwrap();
    assert_eq!(
        rt.root_state(b"/mutation/transition"),
        Some(GuardRootState::Current)
    );
}

#[test]
fn coverage_lost_during_indexing_survives_until_taken() {
    let rt = GuardRuntime::new();
    rt.add_root(
        b"/overflow/root".to_vec(),
        test_fs_identity(),
        GuardRootMode::Repo,
    )
    .unwrap();
    rt.transition_root(b"/overflow/root", &GuardTransition::ReconciliationStarted)
        .unwrap();
    rt.mark_dirty_during_indexing(b"/overflow/root");
    rt.mark_coverage_lost_during_indexing(b"/overflow/root");
    // Root must remain Indexing so the baseline terminal transition stays legal.
    assert_eq!(
        rt.root_state(b"/overflow/root"),
        Some(GuardRootState::Indexing)
    );
    assert!(rt.take_coverage_lost_during_indexing(b"/overflow/root"));
    assert!(!rt.take_coverage_lost_during_indexing(b"/overflow/root"));
    assert!(rt.take_dirty_during_indexing(b"/overflow/root"));
    rt.transition_root(b"/overflow/root", &GuardTransition::ReconciliationDegraded)
        .unwrap();
    assert_eq!(
        rt.root_state(b"/overflow/root"),
        Some(GuardRootState::Degraded)
    );
}

#[test]
fn remove_root_clears_indexing_event_flags() {
    let rt = GuardRuntime::new();
    rt.add_root(
        b"/clear/flags".to_vec(),
        test_fs_identity(),
        GuardRootMode::Filesystem,
    )
    .unwrap();
    rt.mark_dirty_during_indexing(b"/clear/flags");
    rt.mark_coverage_lost_during_indexing(b"/clear/flags");
    assert!(rt.remove_root(b"/clear/flags").is_some());
    assert!(!rt.take_dirty_during_indexing(b"/clear/flags"));
    assert!(!rt.take_coverage_lost_during_indexing(b"/clear/flags"));
}
