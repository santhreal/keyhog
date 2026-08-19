//! WHY: Closes the defect class where GuardPolicyIdentity fields (suppression_digest,
//! keyhogignore_digest, config_digest, source_policy_digest) were left as empty strings,
//! and modifications to policy files (.keyhogignore, .keyhogignore.toml, .keyhog.toml,
//! suppression files) failed to update the policy identity or trigger state transitions
//! to StalePolicy, allowing stale clean attestations to authorize commits under modified
//! policy rules (Row 142).
//!
//! What this does NOT catch: filesystem corruptions that silently alter file bytes without
//! firing watcher events and without altering content hash on read.

use keyhog::testing::daemon::guard_runtime::GuardRuntime;
use keyhog::testing::daemon::server::{
    compute_keyhogignore_digest, compute_root_policy_identity, guard_event_action_with_policy,
    is_policy_path, GuardEventAction, KEYHOG_VERSION,
};
use keyhog_core::guard_state::{
    FilesystemAuthority, FilesystemIdentity, GitCleanAttestation, GitHashAlgorithm,
    GuardPolicyIdentity, GuardReceipt, GuardRootMode, GuardRootState, GuardTransition,
    GUARD_DECODE_POLICY_VERSION, GUARD_REPORT_SEMANTICS_VERSION, GUARD_SCHEMA_VERSION,
};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn sample_fs_identity() -> FilesystemIdentity {
    FilesystemIdentity {
        device: 1,
        inode: 100,
    }
}

fn sample_fs_authority() -> FilesystemAuthority {
    FilesystemAuthority {
        authoritative: true,
        filesystem_type: "ext4".to_string(),
        unauthoritative_reason: None,
    }
}

#[test]
fn row_142_default_guard_policy_identity_has_non_empty_digests() {
    let id = GuardPolicyIdentity::default();
    assert!(!id.build_identity.is_empty());
    assert!(!id.detector_digest.is_empty());
    assert!(!id.suppression_digest.is_empty());
    assert!(!id.keyhogignore_digest.is_empty());
    assert!(!id.config_digest.is_empty());
    assert!(!id.source_policy_digest.is_empty());
    assert_eq!(id.decode_policy_version, GUARD_DECODE_POLICY_VERSION);
    assert_eq!(id.guard_schema_version, GUARD_SCHEMA_VERSION);
    assert_eq!(id.report_semantics_version, GUARD_REPORT_SEMANTICS_VERSION);

    let short = id.short_digest().expect("short digest computation");
    assert_eq!(short.len(), 12);
    assert!(short.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn row_142_from_build_and_detectors_populates_all_digests() {
    let id = GuardPolicyIdentity::from_build_and_detectors("0.5.80", "det-corpus-digest-1234");
    assert_eq!(id.build_identity, "0.5.80");
    assert_eq!(id.detector_digest, "det-corpus-digest-1234");
    assert!(!id.suppression_digest.is_empty());
    assert!(!id.keyhogignore_digest.is_empty());
    assert!(!id.config_digest.is_empty());
    assert!(!id.source_policy_digest.is_empty());
    assert_eq!(id.decode_policy_version, 1);
    assert_eq!(id.guard_schema_version, 1);
    assert_eq!(id.report_semantics_version, 2);
}

#[test]
fn row_142_compute_root_policy_identity_is_deterministic() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    let id1 = compute_root_policy_identity(root, KEYHOG_VERSION, "test-detector-digest");
    let id2 = compute_root_policy_identity(root, KEYHOG_VERSION, "test-detector-digest");

    assert_eq!(id1, id2);
    assert_eq!(id1.build_identity, KEYHOG_VERSION);
    assert_eq!(id1.detector_digest, "test-detector-digest");
    assert!(!id1.suppression_digest.is_empty());
    assert!(!id1.keyhogignore_digest.is_empty());
    assert!(!id1.config_digest.is_empty());
    assert!(!id1.source_policy_digest.is_empty());
}

#[test]
fn row_142_editing_keyhogignore_changes_digest_and_breaks_compatibility() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    let id_initial = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");
    let initial_ignore_digest = compute_keyhogignore_digest(root);
    assert_eq!(id_initial.keyhogignore_digest, initial_ignore_digest);

    // Create .keyhogignore
    let ignore_path = root.join(".keyhogignore");
    fs::write(
        &ignore_path,
        "hash:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    )
    .expect("write .keyhogignore");

    let id_after_create = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");
    assert_ne!(
        id_initial.keyhogignore_digest,
        id_after_create.keyhogignore_digest
    );
    assert!(!id_initial.is_compatible_with(&id_after_create));

    // Modify .keyhogignore
    fs::write(&ignore_path, "path:vendor/**\n").expect("modify .keyhogignore");
    let id_after_modify = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");
    assert_ne!(
        id_after_create.keyhogignore_digest,
        id_after_modify.keyhogignore_digest
    );
    assert!(!id_after_create.is_compatible_with(&id_after_modify));

    // Delete .keyhogignore
    fs::remove_file(&ignore_path).expect("remove .keyhogignore");
    let id_after_delete = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");
    assert_eq!(
        id_initial.keyhogignore_digest,
        id_after_delete.keyhogignore_digest
    );
    assert!(id_initial.is_compatible_with(&id_after_delete));
}

#[test]
fn row_142_editing_keyhogignore_toml_changes_digest_and_breaks_compatibility() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    let id_initial = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");

    // Create .keyhogignore.toml
    let ignore_toml_path = root.join(".keyhogignore.toml");
    fs::write(
        &ignore_toml_path,
        "[[suppress]]\ndetector = \"generic-api-key\"\n",
    )
    .expect("write .keyhogignore.toml");

    let id_created = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");
    assert_ne!(
        id_initial.keyhogignore_digest,
        id_created.keyhogignore_digest
    );
    assert!(!id_initial.is_compatible_with(&id_created));

    // Modify .keyhogignore.toml
    fs::write(
        &ignore_toml_path,
        "[[suppress]]\ndetector = \"aws-access-key-id\"\n",
    )
    .expect("modify .keyhogignore.toml");

    let id_modified = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");
    assert_ne!(
        id_created.keyhogignore_digest,
        id_modified.keyhogignore_digest
    );
    assert!(!id_created.is_compatible_with(&id_modified));
}

#[test]
fn row_142_editing_keyhog_toml_changes_config_digest_and_breaks_compatibility() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    let id_initial = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");

    // Create .keyhog.toml
    let config_path = root.join(".keyhog.toml");
    fs::write(&config_path, "[scan]\nmin_confidence = 0.85\n").expect("write .keyhog.toml");

    let id_created = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");
    assert_ne!(id_initial.config_digest, id_created.config_digest);
    assert!(!id_initial.is_compatible_with(&id_created));

    // Modify .keyhog.toml
    fs::write(&config_path, "[scan]\nmin_confidence = 0.95\n").expect("modify .keyhog.toml");
    let id_modified = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");
    assert_ne!(id_created.config_digest, id_modified.config_digest);
    assert!(!id_created.is_compatible_with(&id_modified));

    // Removing .keyhog.toml returns to initial default config digest
    fs::remove_file(&config_path).expect("remove .keyhog.toml");
    let id_deleted = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");
    assert_eq!(id_initial.config_digest, id_deleted.config_digest);

    // Child directory with its own .keyhog.toml hashes its own config
    let sub_dir = root.join("child");
    fs::create_dir(&sub_dir).expect("create child dir");
    let child_config = sub_dir.join(".keyhog.toml");
    fs::write(&child_config, "[scan]\nmin_confidence = 0.90\n").expect("write child .keyhog.toml");
    let id_child = compute_root_policy_identity(&sub_dir, KEYHOG_VERSION, "det-1");
    assert_ne!(id_initial.config_digest, id_child.config_digest);
}

#[test]
fn row_142_editing_suppression_files_changes_suppression_digest_and_breaks_compatibility() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    let id_initial = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");

    // Add local suppression file
    let supp_path = root.join("suppressions.toml");
    fs::write(
        &supp_path,
        "schema_version = 1\n[[exact]]\ncredential = \"mock-secret\"\n",
    )
    .expect("write suppressions.toml");

    let id_supp = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");
    assert_ne!(id_initial.suppression_digest, id_supp.suppression_digest);
    assert!(!id_initial.is_compatible_with(&id_supp));

    // Add .keyhog/suppressions.toml
    let keyhog_dir = root.join(".keyhog");
    fs::create_dir_all(&keyhog_dir).expect("create .keyhog dir");
    fs::write(
        keyhog_dir.join("suppressions.toml"),
        "schema_version = 1\n[[exact]]\ncredential = \"mock-2\"\n",
    )
    .expect("write .keyhog/suppressions.toml");

    let id_keyhog_supp = compute_root_policy_identity(root, KEYHOG_VERSION, "det-1");
    assert_ne!(
        id_supp.suppression_digest,
        id_keyhog_supp.suppression_digest
    );
    assert!(!id_supp.is_compatible_with(&id_keyhog_supp));
}

#[test]
fn row_142_is_policy_path_classification_total() {
    let policy_paths = [
        Path::new(".keyhogignore"),
        Path::new(".keyhogignore.toml"),
        Path::new(".keyhog.toml"),
        Path::new("test-fixtures.toml"),
        Path::new("suppressions.toml"),
        Path::new("custom.suppressions.toml"),
        Path::new("custom_suppressions.toml"),
        Path::new("sub/dir/.keyhogignore"),
        Path::new("sub/dir/.keyhog.toml"),
        Path::new(".keyhog/suppressions.toml"),
        Path::new(".keyhog/config.toml"),
        Path::new("suppressions/custom.toml"),
    ];

    for p in policy_paths {
        assert!(
            is_policy_path(p),
            "path '{:?}' must be recognized as a policy path",
            p
        );
    }

    let non_policy_paths = [
        Path::new("src/main.rs"),
        Path::new("keyhog.toml"),
        Path::new("Cargo.toml"),
        Path::new("lib/scanner.c"),
        Path::new("data/input.txt"),
    ];

    for p in non_policy_paths {
        assert!(
            !is_policy_path(p),
            "path '{:?}' must NOT be recognized as a policy path",
            p
        );
    }
}

#[test]
fn row_142_guard_event_action_with_policy_handles_all_root_states() {
    let all_states = [
        GuardRootState::Indexing,
        GuardRootState::Current,
        GuardRootState::Dirty,
        GuardRootState::Blocked,
        GuardRootState::Degraded,
        GuardRootState::StalePolicy,
        GuardRootState::Stopped,
    ];

    for state in all_states {
        let action = guard_event_action_with_policy(Some(state), false, true);
        match state {
            GuardRootState::Stopped | GuardRootState::Degraded | GuardRootState::StalePolicy => {
                assert_eq!(
                    action,
                    GuardEventAction::Ignore,
                    "state {:?} must ignore policy event",
                    state
                );
            }
            GuardRootState::Indexing => {
                assert_eq!(
                    action,
                    GuardEventAction::MarkDuringIndexing {
                        coverage_lost: false
                    },
                    "Indexing must mark during indexing without coverage lost"
                );
            }
            GuardRootState::Current | GuardRootState::Dirty | GuardRootState::Blocked => {
                assert_eq!(
                    action,
                    GuardEventAction::Transition(GuardTransition::PolicyChanged),
                    "active state {:?} must transition on PolicyChanged",
                    state
                );
            }
        }
    }
}

#[test]
fn row_142_guard_runtime_policy_change_invalidates_attestations_and_transitions_roots() {
    let rt = GuardRuntime::new();
    let root_path = b"/test/repo".to_vec();

    let initial_id = GuardPolicyIdentity::from_build_and_detectors("0.5.80", "det-v1");
    rt.set_policy_identity(initial_id.clone());

    let record = rt
        .add_root(
            root_path.clone(),
            sample_fs_identity(),
            sample_fs_authority(),
            GuardRootMode::Repo,
        )
        .expect("add root");
    assert_eq!(record.state, GuardRootState::Stopped);

    // Transition Stopped -> ReconciliationStarted -> Indexing -> Current
    rt.transition_root(&root_path, &GuardTransition::ReconciliationStarted)
        .expect("start reconcile");
    assert_eq!(rt.root_state(&root_path), Some(GuardRootState::Indexing));

    rt.transition_root(&root_path, &GuardTransition::ReconciliationClean)
        .expect("finish reconcile");
    assert_eq!(rt.root_state(&root_path), Some(GuardRootState::Current));

    // Insert clean attestation
    let att = GitCleanAttestation {
        hash_algorithm: GitHashAlgorithm::Sha1,
        blob_oid: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
        object_size: 1024,
        policy_identity: initial_id.clone(),
        last_seen_sequence: 1,
    };
    rt.insert_attestation(att);
    let policy_short = initial_id.short_digest().unwrap();
    assert!(rt
        .lookup_attestation(
            GitHashAlgorithm::Sha1,
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            &policy_short
        )
        .is_some());

    // Policy change: modify suppression or config digest
    let mut changed_id = initial_id.clone();
    changed_id.keyhogignore_digest = "changed-ignore-digest".to_string();
    assert!(!initial_id.is_compatible_with(&changed_id));

    // Setting the new policy identity triggers invalidation and transition to StalePolicy
    rt.set_policy_identity(changed_id.clone());
    assert_eq!(rt.root_state(&root_path), Some(GuardRootState::StalePolicy));

    // Stale attestations under old policy are invalidated
    assert!(rt
        .lookup_attestation(
            GitHashAlgorithm::Sha1,
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            &policy_short
        )
        .is_none());

    // Reconciliation repair cycle from StalePolicy:
    // StalePolicy -> RepairStarted -> Indexing -> ReconciliationClean -> Current
    rt.transition_root(&root_path, &GuardTransition::RepairStarted)
        .expect("repair started");
    assert_eq!(rt.root_state(&root_path), Some(GuardRootState::Indexing));

    rt.transition_root(&root_path, &GuardTransition::ReconciliationClean)
        .expect("repair finish");
    assert_eq!(rt.root_state(&root_path), Some(GuardRootState::Current));
}

#[test]
fn row_142_guard_receipt_carries_fully_populated_policy_identity() {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // Create policy files
    fs::write(root.join(".keyhogignore"), "path:target/**\n").expect("write ignore");
    fs::write(root.join(".keyhog.toml"), "[scan]\nmin_confidence = 0.8\n").expect("write config");

    let policy_identity = compute_root_policy_identity(root, KEYHOG_VERSION, "det-live");

    let receipt = GuardReceipt {
        objects_requested: 10,
        objects_hit: 8,
        objects_scanned: 2,
        objects_skipped: 0,
        bytes_requested: 10000,
        bytes_hit: 8000,
        bytes_scanned: 2000,
        findings_count: 0,
        coverage_gaps: 0,
        terminal_state: GuardRootState::Current,
        policy_identity: policy_identity.clone(),
        terminal_sequence: 42,
    };

    assert!(receipt.validate_conservation().is_ok());
    assert_eq!(receipt.policy_identity.build_identity, KEYHOG_VERSION);
    assert_eq!(receipt.policy_identity.detector_digest, "det-live");
    assert_ne!(
        receipt.policy_identity.keyhogignore_digest,
        GuardPolicyIdentity::default_keyhogignore_digest()
    );
    assert_ne!(
        receipt.policy_identity.config_digest,
        GuardPolicyIdentity::default_config_digest()
    );
}

#[test]
fn row_142_independent_root_policy_identities_do_not_clobber_each_other() {
    let rt = GuardRuntime::new();
    let root1 = b"/repo/project-a".to_vec();
    let root2 = b"/repo/project-b".to_vec();

    let default_id = GuardPolicyIdentity::from_build_and_detectors("0.5.80", "det-default");
    rt.set_policy_identity(default_id.clone());

    let mut id_a = default_id.clone();
    id_a.keyhogignore_digest = "ignore-a".to_string();
    let mut id_b = default_id.clone();
    id_b.keyhogignore_digest = "ignore-b".to_string();

    rt.set_root_policy_identity(&root1, id_a.clone());
    rt.set_root_policy_identity(&root2, id_b.clone());

    assert_eq!(rt.get_root_policy_identity(&root1), Some(id_a));
    assert_eq!(rt.get_root_policy_identity(&root2), Some(id_b));
    // Default identity is not clobbered by set_root_policy_identity
    assert_eq!(rt.policy_identity(), Some(default_id));
}

#[test]
fn row_142_overflow_takes_precedence_over_policy_change_in_event_action() {
    let action = guard_event_action_with_policy(Some(GuardRootState::Current), true, true);
    assert_eq!(
        action,
        GuardEventAction::Transition(GuardTransition::CoverageLost),
        "overflow with policy change must transition to CoverageLost"
    );
}
