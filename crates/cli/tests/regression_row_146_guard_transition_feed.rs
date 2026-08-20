#![cfg(unix)]
//! WHY: Closes defect class where perpetual guard state machine transitions occur invisibly or
//! without causal attribution across roots, making daemon decisions uninspectable to operators
//! and automated health checkers (Row 146).
//!
//! Continuous guard transition feed / event log surface:
//! - Expose recent state transitions with causes across registered roots for daemon and CLI inspectability.
//! - Guard exposes continuous transition history and events with causal attribution across all roots.
//! - Every state machine event and commit transaction outcome logs an exact timestamped,
//!   sequenced transition record with prior state, new state, trigger event, and causal explanation.
//! - Root records retain per-root transition history for `guard status` inspectability.
//! - Global feed ring buffer retains cross-root transitions for `guard feed` inspectability.
//! - Transitions include policy change reconciliation, watcher event ingestion, and transaction commits.
//!
//! WHAT IT DOES NOT CATCH:
//! Unrecorded kernel-level process terminations (SIGKILL) before transition records are materialized in memory.

use keyhog::testing::daemon::guard_runtime::GuardRuntime;
use keyhog::testing::daemon::protocol::Request;
use keyhog_core::guard_state::{
    FilesystemAuthority, FilesystemIdentity, GuardPolicyIdentity, GuardReceipt, GuardRootMode,
    GuardRootState, GuardTransition, GuardTransitionRecord,
};
use std::collections::HashSet;

fn test_fs_identity(dev: u64, ino: u64) -> FilesystemIdentity {
    FilesystemIdentity {
        device: dev,
        inode: ino,
    }
}

fn test_fs_authority() -> FilesystemAuthority {
    FilesystemAuthority::authoritative("ext4")
}

fn test_policy_identity(digest: &str) -> GuardPolicyIdentity {
    GuardPolicyIdentity {
        build_identity: "keyhog-0.5.80".to_string(),
        detector_digest: digest.to_string(),
        suppression_digest: String::new(),
        keyhogignore_digest: String::new(),
        config_digest: String::new(),
        decode_policy_version: 1,
        source_policy_digest: String::new(),
        guard_schema_version: keyhog_core::guard_state::GUARD_SCHEMA_VERSION,
        report_semantics_version: keyhog_core::guard_state::GUARD_REPORT_SEMANTICS_VERSION,
    }
}

#[test]
fn all_guard_transitions_and_states_derived_at_runtime() {
    let states = GuardRootState::all();
    let transitions = GuardTransition::all();

    assert_eq!(states.len(), 7, "must derive all 7 guard states");
    assert_eq!(
        transitions.len(),
        12,
        "must derive all 12 guard transitions"
    );

    // Verify all transition labels are non-empty and unique
    let mut labels = HashSet::new();
    for t in transitions {
        assert!(!t.label().is_empty(), "transition label must not be empty");
        assert!(
            labels.insert(t.label()),
            "transition label '{}' must be unique",
            t.label()
        );
    }

    // Verify GuardTransitionRecord serialization round-trip
    let record = GuardTransitionRecord {
        canonical_path: b"/var/repo/alpha".to_vec(),
        sequence: 42,
        timestamp: 1_700_000_000,
        from_state: GuardRootState::Indexing,
        to_state: GuardRootState::Current,
        event: GuardTransition::ReconciliationClean,
        cause: "baseline reconciliation clean: 120 files scanned, 0 findings".to_string(),
    };

    let serialized = serde_json::to_string(&record).expect("serialize GuardTransitionRecord");
    let deserialized: GuardTransitionRecord =
        serde_json::from_str(&serialized).expect("deserialize GuardTransitionRecord");
    assert_eq!(record, deserialized);
}

#[test]
fn transition_feed_records_causal_attribution_across_roots() {
    let rt = GuardRuntime::new();
    let root_a = b"/workspace/project_a".to_vec();
    let root_b = b"/workspace/project_b".to_vec();

    rt.add_root(
        root_a.clone(),
        test_fs_identity(1, 101),
        test_fs_authority(),
        GuardRootMode::Repo,
    )
    .expect("add root a");

    rt.add_root(
        root_b.clone(),
        test_fs_identity(1, 102),
        test_fs_authority(),
        GuardRootMode::Filesystem,
    )
    .expect("add root b");

    // Root A: Stopped -> Indexing -> Current -> Dirty -> Blocked -> Degraded -> Indexing (repair) -> Current
    rt.transition_root_with_cause(
        &root_a,
        &GuardTransition::ReconciliationStarted,
        "initial reconciliation started",
    )
    .expect("start A");

    rt.transition_root_with_cause(
        &root_a,
        &GuardTransition::ReconciliationClean,
        "baseline clean: 50 files scanned, 0 findings",
    )
    .expect("clean A");

    rt.transition_root_with_cause(
        &root_a,
        &GuardTransition::EventAccepted,
        "filesystem watcher: 2 files modified in src/",
    )
    .expect("dirty A");

    rt.transition_root_with_cause(
        &root_a,
        &GuardTransition::EventsFindings,
        "event batch produced 1 unsuppressed finding",
    )
    .expect("findings A");

    rt.transition_root_with_cause(
        &root_a,
        &GuardTransition::CoverageLost,
        "watcher overflow: kernel queue lost change events",
    )
    .expect("degraded A");

    rt.transition_root_with_cause(
        &root_a,
        &GuardTransition::RepairStarted,
        "manual repair initiated to restore coverage",
    )
    .expect("repair A");

    rt.transition_root_with_cause(
        &root_a,
        &GuardTransition::ReconciliationClean,
        "repair reconciliation complete: clean baseline",
    )
    .expect("re-clean A");

    // Root B: Stopped -> Indexing -> Blocked
    rt.transition_root_with_cause(
        &root_b,
        &GuardTransition::ReconciliationStarted,
        "root b initial scan",
    )
    .expect("start B");

    rt.transition_root_with_cause(
        &root_b,
        &GuardTransition::ReconciliationFindings,
        "initial baseline found 3 plaintext credentials",
    )
    .expect("findings B");

    // Inspect cross-root transition feed
    let feed = rt.transition_feed(None, None);
    assert_eq!(
        feed.len(),
        9,
        "feed must contain all 9 transition events across roots"
    );

    // Sequence numbers must be strictly increasing
    for i in 1..feed.len() {
        assert!(
            feed[i].sequence > feed[i - 1].sequence,
            "transition sequences must be strictly monotonically increasing ({} <= {})",
            feed[i].sequence,
            feed[i - 1].sequence
        );
    }

    // Verify individual causal attributions
    assert_eq!(feed[0].canonical_path, root_a);
    assert_eq!(feed[0].from_state, GuardRootState::Stopped);
    assert_eq!(feed[0].to_state, GuardRootState::Indexing);
    assert_eq!(feed[0].event, GuardTransition::ReconciliationStarted);
    assert_eq!(feed[0].cause, "initial reconciliation started");

    assert_eq!(feed[1].canonical_path, root_a);
    assert_eq!(feed[1].from_state, GuardRootState::Indexing);
    assert_eq!(feed[1].to_state, GuardRootState::Current);
    assert_eq!(feed[1].event, GuardTransition::ReconciliationClean);
    assert_eq!(
        feed[1].cause,
        "baseline clean: 50 files scanned, 0 findings"
    );

    assert_eq!(feed[4].canonical_path, root_a);
    assert_eq!(feed[4].from_state, GuardRootState::Blocked);
    assert_eq!(feed[4].to_state, GuardRootState::Degraded);
    assert_eq!(feed[4].event, GuardTransition::CoverageLost);
    assert_eq!(
        feed[4].cause,
        "watcher overflow: kernel queue lost change events"
    );

    assert_eq!(feed[7].canonical_path, root_b);
    assert_eq!(feed[7].from_state, GuardRootState::Stopped);
    assert_eq!(feed[7].to_state, GuardRootState::Indexing);
    assert_eq!(feed[7].cause, "root b initial scan");

    assert_eq!(feed[8].canonical_path, root_b);
    assert_eq!(feed[8].from_state, GuardRootState::Indexing);
    assert_eq!(feed[8].to_state, GuardRootState::Blocked);
    assert_eq!(
        feed[8].cause,
        "initial baseline found 3 plaintext credentials"
    );
}

#[test]
fn transition_feed_filters_by_root_and_limits() {
    let rt = GuardRuntime::new();
    let root_1 = b"/workspace/root_1".to_vec();
    let root_2 = b"/workspace/root_2".to_vec();

    rt.add_root(
        root_1.clone(),
        test_fs_identity(1, 1),
        test_fs_authority(),
        GuardRootMode::Repo,
    )
    .unwrap();
    rt.add_root(
        root_2.clone(),
        test_fs_identity(1, 2),
        test_fs_authority(),
        GuardRootMode::Repo,
    )
    .unwrap();

    rt.transition_root_with_cause(
        &root_1,
        &GuardTransition::ReconciliationStarted,
        "root 1 start",
    )
    .unwrap();
    rt.transition_root_with_cause(
        &root_2,
        &GuardTransition::ReconciliationStarted,
        "root 2 start",
    )
    .unwrap();
    rt.transition_root_with_cause(
        &root_1,
        &GuardTransition::ReconciliationClean,
        "root 1 clean",
    )
    .unwrap();
    rt.transition_root_with_cause(
        &root_2,
        &GuardTransition::ReconciliationFindings,
        "root 2 findings",
    )
    .unwrap();

    // Filter by root 1
    let feed_1 = rt.transition_feed(Some(&root_1), None);
    assert_eq!(feed_1.len(), 2);
    assert_eq!(feed_1[0].cause, "root 1 start");
    assert_eq!(feed_1[1].cause, "root 1 clean");

    // Filter by root 2
    let feed_2 = rt.transition_feed(Some(&root_2), None);
    assert_eq!(feed_2.len(), 2);
    assert_eq!(feed_2[0].cause, "root 2 start");
    assert_eq!(feed_2[1].cause, "root 2 findings");

    // Limit across all
    let limited = rt.transition_feed(None, Some(3));
    assert_eq!(limited.len(), 3);
    assert_eq!(limited[0].cause, "root 2 start");
    assert_eq!(limited[1].cause, "root 1 clean");
    assert_eq!(limited[2].cause, "root 2 findings");
}

#[test]
fn transition_feed_retains_per_root_history_in_record() {
    let rt = GuardRuntime::new();
    let root = b"/workspace/history_test".to_vec();

    rt.add_root(
        root.clone(),
        test_fs_identity(1, 50),
        test_fs_authority(),
        GuardRootMode::Repo,
    )
    .unwrap();

    rt.transition_root_with_cause(
        &root,
        &GuardTransition::ReconciliationStarted,
        "step 1: start",
    )
    .unwrap();
    rt.transition_root_with_cause(
        &root,
        &GuardTransition::ReconciliationClean,
        "step 2: clean",
    )
    .unwrap();

    let record = rt.root_record(&root).expect("root record must exist");
    assert_eq!(
        record.recent_transitions.len(),
        2,
        "root record must preserve local transition history"
    );
    assert_eq!(record.recent_transitions[0].cause, "step 1: start");
    assert_eq!(record.recent_transitions[1].cause, "step 2: clean");
}

#[test]
fn commit_transaction_receipt_transitions_record_causes() {
    let rt = GuardRuntime::new();
    let root = b"/workspace/commit_test".to_vec();

    rt.add_root(
        root.clone(),
        test_fs_identity(1, 77),
        test_fs_authority(),
        GuardRootMode::Repo,
    )
    .unwrap();

    // Clean commit receipt
    let clean_receipt = GuardReceipt {
        objects_requested: 10,
        objects_hit: 8,
        objects_scanned: 2,
        objects_skipped: 0,
        bytes_requested: 5000,
        bytes_hit: 4000,
        bytes_scanned: 1000,
        findings_count: 0,
        coverage_gaps: 0,
        terminal_state: GuardRootState::Current,
        policy_identity: test_policy_identity("detector-digest-1"),
        terminal_sequence: 1,
    };

    rt.update_root_after_commit(&root, clean_receipt)
        .expect("update clean commit");

    let feed = rt.transition_feed(Some(&root), None);
    assert_eq!(feed.len(), 1);
    assert_eq!(feed[0].from_state, GuardRootState::Stopped);
    assert_eq!(feed[0].to_state, GuardRootState::Current);
    assert_eq!(feed[0].event, GuardTransition::EventsClean);
    assert!(
        feed[0].cause.contains("commit transaction clean"),
        "cause must describe clean commit transaction: {}",
        feed[0].cause
    );
    assert!(
        feed[0].cause.contains("10 objects"),
        "cause must include object count: {}",
        feed[0].cause
    );

    // Blocked commit receipt
    let blocked_receipt = GuardReceipt {
        objects_requested: 5,
        objects_hit: 3,
        objects_scanned: 2,
        objects_skipped: 0,
        bytes_requested: 2000,
        bytes_hit: 1200,
        bytes_scanned: 800,
        findings_count: 2,
        coverage_gaps: 0,
        terminal_state: GuardRootState::Blocked,
        policy_identity: test_policy_identity("detector-digest-1"),
        terminal_sequence: 2,
    };

    rt.update_root_after_commit(&root, blocked_receipt)
        .expect("update blocked commit");

    let feed_after = rt.transition_feed(Some(&root), None);
    assert_eq!(feed_after.len(), 2);
    assert_eq!(feed_after[1].from_state, GuardRootState::Current);
    assert_eq!(feed_after[1].to_state, GuardRootState::Blocked);
    assert_eq!(feed_after[1].event, GuardTransition::EventsFindings);
    assert!(
        feed_after[1]
            .cause
            .contains("blocked: 2 unsuppressed findings"),
        "cause must name findings count: {}",
        feed_after[1].cause
    );
}

#[test]
fn policy_identity_change_records_transition_with_cause() {
    let rt = GuardRuntime::new();
    let root = b"/workspace/policy_test".to_vec();

    rt.set_policy_identity(test_policy_identity("detector-v1"));
    rt.add_root(
        root.clone(),
        test_fs_identity(1, 88),
        test_fs_authority(),
        GuardRootMode::Repo,
    )
    .unwrap();

    rt.transition_root_with_cause(
        &root,
        &GuardTransition::ReconciliationStarted,
        "initial reconcile",
    )
    .unwrap();
    rt.transition_root_with_cause(
        &root,
        &GuardTransition::ReconciliationClean,
        "initial clean",
    )
    .unwrap();

    assert_eq!(rt.root_state(&root), Some(GuardRootState::Current));

    // Changing policy identity transitions Current roots to StalePolicy
    rt.set_policy_identity(test_policy_identity("detector-v2"));

    assert_eq!(rt.root_state(&root), Some(GuardRootState::StalePolicy));

    let feed = rt.transition_feed(Some(&root), None);
    assert_eq!(feed.len(), 3);
    assert_eq!(feed[2].from_state, GuardRootState::Current);
    assert_eq!(feed[2].to_state, GuardRootState::StalePolicy);
    assert_eq!(feed[2].event, GuardTransition::PolicyChanged);
    assert!(
        feed[2].cause.contains("policy identity changed"),
        "cause must identify policy change: {}",
        feed[2].cause
    );
}

#[test]
fn wire_protocol_guard_feed_and_status_roundtrip() {
    // Test Request::GuardFeed wire serialization and deserialization
    let feed_request = Request::GuardFeed {
        root: Some("/var/project".to_string()),
        limit: Some(25),
    };
    let req_serialized = serde_json::to_string(&feed_request).expect("serialize GuardFeed request");
    let req_deserialized: Request =
        serde_json::from_str(&req_serialized).expect("deserialize GuardFeed request");
    match req_deserialized {
        Request::GuardFeed { root, limit } => {
            assert_eq!(root, Some("/var/project".to_string()));
            assert_eq!(limit, Some(25));
        }
        other => panic!("expected GuardFeed, got {:?}", other),
    }

    // Test GuardFeedResult JSON shape and deserialization
    let feed_json = serde_json::json!({
        "kind": "guard_feed_result",
        "transitions": [
            {
                "root": "/var/project",
                "sequence": 15,
                "timestamp": 1_700_000_100,
                "from_state": "indexing",
                "to_state": "current",
                "event": "reconciliation-clean",
                "cause": "baseline reconciliation clean: 10 files, 0 findings"
            }
        ]
    });
    let serialized = serde_json::to_string(&feed_json).expect("serialize feed json");
    let val: serde_json::Value = serde_json::from_str(&serialized).expect("parse feed json");
    assert_eq!(val["kind"], "guard_feed_result");
    assert_eq!(val["transitions"][0]["root"], "/var/project");
    assert_eq!(val["transitions"][0]["sequence"], 15);
    assert_eq!(val["transitions"][0]["from_state"], "indexing");
    assert_eq!(val["transitions"][0]["to_state"], "current");
    assert_eq!(val["transitions"][0]["event"], "reconciliation-clean");
    assert_eq!(
        val["transitions"][0]["cause"],
        "baseline reconciliation clean: 10 files, 0 findings"
    );
}

#[test]
fn set_root_policy_identity_records_transition_and_isolates_roots() {
    let rt = GuardRuntime::new();
    let root_a = b"/workspace/project_alpha".to_vec();
    let root_b = b"/workspace/project_beta".to_vec();

    rt.add_root(
        root_a.clone(),
        test_fs_identity(1, 101),
        test_fs_authority(),
        GuardRootMode::Repo,
    )
    .unwrap();
    rt.add_root(
        root_b.clone(),
        test_fs_identity(1, 102),
        test_fs_authority(),
        GuardRootMode::Repo,
    )
    .unwrap();

    rt.set_root_policy_identity(&root_a, test_policy_identity("det-a1"));
    rt.set_root_policy_identity(&root_b, test_policy_identity("det-b1"));

    rt.transition_root_with_cause(
        &root_a,
        &GuardTransition::ReconciliationStarted,
        "reconcile A",
    )
    .unwrap();
    rt.transition_root_with_cause(&root_a, &GuardTransition::ReconciliationClean, "clean A")
        .unwrap();
    assert_eq!(rt.root_state(&root_a), Some(GuardRootState::Current));

    rt.transition_root_with_cause(
        &root_b,
        &GuardTransition::ReconciliationStarted,
        "reconcile B",
    )
    .unwrap();
    rt.transition_root_with_cause(&root_b, &GuardTransition::ReconciliationClean, "clean B")
        .unwrap();
    assert_eq!(rt.root_state(&root_b), Some(GuardRootState::Current));

    // Update policy identity for Root A only
    rt.set_root_policy_identity(&root_a, test_policy_identity("det-a2"));

    // Root A should transition to StalePolicy and record it in the feed
    assert_eq!(rt.root_state(&root_a), Some(GuardRootState::StalePolicy));
    // Root B should remain untouched in Current
    assert_eq!(rt.root_state(&root_b), Some(GuardRootState::Current));

    let feed_a = rt.transition_feed(Some(&root_a), None);
    assert_eq!(feed_a.len(), 3);
    assert_eq!(feed_a[2].from_state, GuardRootState::Current);
    assert_eq!(feed_a[2].to_state, GuardRootState::StalePolicy);
    assert_eq!(feed_a[2].event, GuardTransition::PolicyChanged);
    assert!(
        feed_a[2].cause.contains("policy identity changed"),
        "cause must describe policy change: {}",
        feed_a[2].cause
    );

    // Verify root_policy_identity returns root-specific identity
    assert_eq!(
        rt.root_policy_identity(&root_a).unwrap().detector_digest,
        "det-a2"
    );
    assert_eq!(
        rt.root_policy_identity(&root_b).unwrap().detector_digest,
        "det-b1"
    );
}

#[test]
fn guard_event_action_with_policy_prioritizes_overflow_and_prevents_duplicate_transitions() {
    use keyhog::testing::daemon::server::{guard_event_action_with_policy, GuardEventAction};

    // Overflow wins over policy change
    let action = guard_event_action_with_policy(Some(GuardRootState::Current), true, true);
    assert_eq!(
        action,
        GuardEventAction::Transition(GuardTransition::CoverageLost)
    );

    // Policy change on StalePolicy yields Ignore (no double transition)
    let action_stale =
        guard_event_action_with_policy(Some(GuardRootState::StalePolicy), false, true);
    assert_eq!(action_stale, GuardEventAction::Ignore);

    // Overflow on StalePolicy yields CoverageLost -> Degraded
    let action_stale_overflow =
        guard_event_action_with_policy(Some(GuardRootState::StalePolicy), true, false);
    assert_eq!(
        action_stale_overflow,
        GuardEventAction::Transition(GuardTransition::CoverageLost)
    );
}
