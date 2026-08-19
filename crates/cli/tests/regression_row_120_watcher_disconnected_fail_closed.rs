//! WHY: Closes defect class where filesystem watcher channel disconnection or backend
//! worker thread death/panic silently stops event monitoring while leaving roots in Current.
//! (Row 120)
//!
//! When the watcher event channel disconnects (mpsc::TryRecvError::Disconnected), the system
//! must fail closed: fan ReconcileSubtree to all registered roots, transition active roots
//! out of Current into Degraded, and record a named, operator-visible disconnection reason.
//! Disabled watcher mode must explicitly report itself as unmonitored / not watching rather
//! than quiet.
//!
//! WHAT IT DOES NOT CATCH:
//! Physical disk detachment or hardware controller bus reset during in-flight DMA operations.

use keyhog::daemon::guard_runtime::GuardRuntime;
use keyhog::daemon::guard_watcher::GuardWatcher;
use keyhog::daemon::server::{guard_event_action, GuardEventAction};
use keyhog_core::guard_state::{
    FilesystemIdentity, GuardRootMode, GuardRootState, GuardTransition,
};
use keyhog_sources::guard::{GuardEvent, GuardReconciliationConfig};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc;
use tempfile::tempdir;

fn test_fs_identity() -> FilesystemIdentity {
    FilesystemIdentity {
        device: 1,
        inode: 42,
    }
}


#[test]
fn disabled_watcher_reports_unmonitored_not_quiet() {
    let watcher = GuardWatcher::new_disabled();
    assert!(
        watcher.is_disabled(),
        "disabled watcher must report is_disabled = true"
    );
    assert!(
        !watcher.is_watching(),
        "disabled watcher must report is_watching = false"
    );
    assert_eq!(
        watcher.watcher_status(),
        "unmonitored",
        "disabled watcher mode must explicitly report 'unmonitored'"
    );

    let events = watcher.poll_events();
    assert!(
        events.is_empty(),
        "disabled watcher must produce no spurious events"
    );
}

#[test]
fn watcher_disconnection_fans_reconcile_subtree_to_all_roots() {
    let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
    let mut watcher =
        GuardWatcher::with_channel_for_test(rx, GuardReconciliationConfig::default());

    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();
    let dir_c = tempdir().unwrap();

    watcher.add_root(dir_a.path().to_path_buf()).unwrap();
    watcher.add_root(dir_b.path().to_path_buf()).unwrap();
    watcher.add_root(dir_c.path().to_path_buf()).unwrap();

    assert_eq!(watcher.root_count(), 3);
    assert_eq!(watcher.watcher_status(), "watching");
    assert!(!watcher.is_disconnected());
    assert!(watcher.disconnection_reason().is_none());

    // Simulate backend thread exit / panic / channel drop
    drop(tx);

    let events = watcher.poll_events();
    assert!(
        watcher.is_disconnected(),
        "watcher must report is_disconnected = true after channel drop"
    );
    assert_eq!(
        watcher.watcher_status(),
        "disconnected",
        "watcher status must report 'disconnected'"
    );
    let reason = watcher.disconnection_reason();
    assert!(
        reason.is_some(),
        "disconnection reason must be recorded"
    );
    let reason_str = reason.unwrap();
    assert!(
        reason_str.contains("watcher backend disconnected"),
        "disconnection reason must be named and operator-visible: got '{reason_str}'"
    );

    // Fail-closed invariant: Every watched root must receive a ReconcileSubtree event
    assert_eq!(
        events.len(),
        3,
        "every registered root must receive subtree reconciliation"
    );
    let returned_roots: HashSet<PathBuf> = events.iter().map(|(r, _)| r.clone()).collect();
    assert!(returned_roots.contains(dir_a.path()));
    assert!(returned_roots.contains(dir_b.path()));
    assert!(returned_roots.contains(dir_c.path()));

    for (root, evts) in events {
        assert_eq!(
            evts.len(),
            1,
            "root {} should have exactly one ReconcileSubtree event",
            root.display()
        );
        assert!(
            matches!(&evts[0], GuardEvent::ReconcileSubtree(p) if p == &root),
            "event must be ReconcileSubtree for root {}",
            root.display()
        );
    }
}

#[test]
fn watcher_disconnection_transitions_current_roots_to_degraded() {
    let rt = GuardRuntime::new();
    let root_path = b"/test/guarded/repo".to_vec();

    rt.add_root(
        root_path.clone(),
        test_fs_identity(),
        GuardRootMode::Repo,
    )
    .unwrap();

    // Transition Stopped -> Indexing -> Current
    rt.transition_root(&root_path, &GuardTransition::ReconciliationStarted)
        .unwrap();
    rt.transition_root(&root_path, &GuardTransition::ReconciliationClean)
        .unwrap();

    assert_eq!(
        rt.root_state(&root_path),
        Some(GuardRootState::Current),
        "root must start in Current state"
    );

    // Simulate watcher disconnect event action on a Current root
    let action = guard_event_action(rt.root_state(&root_path), true);
    assert_eq!(
        action,
        GuardEventAction::Transition(GuardTransition::CoverageLost),
        "disconnection on Current root must trigger CoverageLost transition"
    );

    match action {
        GuardEventAction::Transition(transition) => {
            let new_state = rt.transition_root(&root_path, &transition).unwrap();
            assert_eq!(
                new_state,
                GuardRootState::Degraded,
                "Current root must transition to Degraded on CoverageLost"
            );
        }
        other => panic!("expected Transition, got {other:?}"),
    }

    assert_eq!(
        rt.root_state(&root_path),
        Some(GuardRootState::Degraded),
        "root must not remain in Current when watcher disconnects"
    );
}

#[test]
fn watcher_disconnection_transitions_all_active_states_to_degraded_or_coverage_lost() {
    let all_states = GuardRootState::all();

    for &state in all_states {
        let action = guard_event_action(Some(state), true);
        match state {
            GuardRootState::Stopped => {
                assert_eq!(
                    action,
                    GuardEventAction::Ignore,
                    "Stopped root ignores watcher overflow"
                );
            }
            GuardRootState::Indexing => {
                assert_eq!(
                    action,
                    GuardEventAction::MarkDuringIndexing { coverage_lost: true },
                    "Indexing root marks coverage_lost_during_indexing"
                );
            }
            GuardRootState::StalePolicy => {
                assert_eq!(
                    action,
                    GuardEventAction::Ignore,
                    "StalePolicy root is already in repair state"
                );
            }
            GuardRootState::Current | GuardRootState::Dirty | GuardRootState::Blocked | GuardRootState::Degraded => {
                assert_eq!(
                    action,
                    GuardEventAction::Transition(GuardTransition::CoverageLost),
                    "State {:?} must transition via CoverageLost on disconnection",
                    state
                );
            }
        }
    }
}

#[test]
fn watcher_disconnection_during_indexing_forces_degraded_baseline_completion() {
    let rt = GuardRuntime::new();
    let root_path = b"/test/indexing/repo".to_vec();

    rt.add_root(
        root_path.clone(),
        test_fs_identity(),
        GuardRootMode::Repo,
    )
    .unwrap();

    rt.transition_root(&root_path, &GuardTransition::ReconciliationStarted)
        .unwrap();
    assert_eq!(rt.root_state(&root_path), Some(GuardRootState::Indexing));

    // Watcher disconnects while Indexing
    let action = guard_event_action(rt.root_state(&root_path), true);
    assert_eq!(
        action,
        GuardEventAction::MarkDuringIndexing { coverage_lost: true }
    );
    rt.mark_coverage_lost_during_indexing(&root_path);

    // Baseline walk completes clean, but coverage was lost during walk
    let had_coverage_loss = rt.take_coverage_lost_during_indexing(&root_path);
    assert!(had_coverage_loss);

    let terminal_transition = if had_coverage_loss {
        GuardTransition::ReconciliationDegraded
    } else {
        GuardTransition::ReconciliationClean
    };

    let terminal_state = rt.transition_root(&root_path, &terminal_transition).unwrap();
    assert_eq!(
        terminal_state,
        GuardRootState::Degraded,
        "Indexing root that lost watcher coverage must end Degraded, not Current"
    );
}

#[test]
fn add_root_fails_closed_when_watcher_is_disconnected() {
    let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
    let mut watcher =
        GuardWatcher::with_channel_for_test(rx, GuardReconciliationConfig::default());

    drop(tx);
    let _ = watcher.poll_events();
    assert!(watcher.is_disconnected());

    let dir = tempdir().unwrap();
    let result = watcher.add_root(dir.path().to_path_buf());
    assert!(
        result.is_err(),
        "add_root must fail when watcher backend is disconnected"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("watcher backend disconnected"),
        "error message must name the disconnected watcher condition: got '{err_msg}'"
    );
}

#[test]
fn runtime_tracks_named_watcher_disconnection_reason() {
    let rt = GuardRuntime::new();
    assert!(!rt.is_watcher_disconnected());
    assert!(rt.watcher_disconnection_reason().is_none());

    let reason = "notify event channel closed unexpectedly";
    rt.record_watcher_disconnection(reason);

    assert!(rt.is_watcher_disconnected());
    assert_eq!(
        rt.watcher_disconnection_reason().as_deref(),
        Some(reason)
    );
    assert_eq!(
        rt.watcher_status().as_deref(),
        Some("disconnected: notify event channel closed unexpectedly")
    );
}
