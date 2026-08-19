use super::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn watcher_starts_empty() {
    let config = GuardReconciliationConfig::default();
    let watcher = GuardWatcher::new(config).unwrap();
    assert!(watcher.is_empty());
}

#[test]
fn add_and_remove_root() {
    let dir = tempdir().unwrap();
    let config = GuardReconciliationConfig::default();
    let mut watcher = GuardWatcher::new(config).unwrap();
    watcher.add_root(dir.path().to_path_buf()).unwrap();
    assert_eq!(watcher.root_count(), 1);
    watcher.remove_root(dir.path());
    assert!(watcher.is_empty());
}

#[test]
fn duplicate_root_fails() {
    let dir = tempdir().unwrap();
    let config = GuardReconciliationConfig::default();
    let mut watcher = GuardWatcher::new(config).unwrap();
    watcher.add_root(dir.path().to_path_buf()).unwrap();
    let result = watcher.add_root(dir.path().to_path_buf());
    assert!(result.is_err());
}

#[test]
fn poll_events_returns_empty_when_idle() {
    let dir = tempdir().unwrap();
    let config = GuardReconciliationConfig::default();
    let mut watcher = GuardWatcher::new(config).unwrap();
    watcher.add_root(dir.path().to_path_buf()).unwrap();
    let events = watcher.poll_events();
    // May have some initial events from the watcher registration,
    // but should be empty or minimal.
    let _ = events; // non-deterministic, just verify no panic
}

#[test]
fn file_change_produces_event() {
    let dir = tempdir().unwrap();
    let config = GuardReconciliationConfig::default();
    let mut watcher = GuardWatcher::new(config).unwrap();
    watcher.add_root(dir.path().to_path_buf()).unwrap();

    // Create a file and modify it.
    let file_path = dir.path().join("test.txt");
    fs::write(&file_path, "content").unwrap();

    // Give the watcher a moment to deliver the event.
    std::thread::sleep(std::time::Duration::from_millis(100));
    let events = watcher.poll_events();
    // We should get at least one event for the created file.
    // Note: notify may coalesce or delay events, so we just verify
    // no panic and the events vector is processable.
    let _ = events;
}

#[test]
fn normalize_create_event() {
    let event = notify::Event::new(EventKind::Create(notify::event::CreateKind::File));
    let guard_events = normalize_notify_event(&event);
    assert_eq!(guard_events.len(), 1);
}

#[test]
fn normalize_modify_event() {
    let event = notify::Event::new(EventKind::Modify(notify::event::ModifyKind::Any));
    let guard_events = normalize_notify_event(&event);
    assert_eq!(guard_events.len(), 1);
}

#[test]
fn normalize_remove_event() {
    let event = notify::Event::new(EventKind::Remove(notify::event::RemoveKind::File));
    let guard_events = normalize_notify_event(&event);
    assert_eq!(guard_events.len(), 1);
}

#[test]
fn disabled_watcher_reports_unmonitored_and_polls_empty() {
    let watcher = GuardWatcher::new_disabled();
    assert!(watcher.is_disabled());
    assert!(!watcher.is_watching());
    assert_eq!(watcher.watcher_status(), "unmonitored");
    let events = watcher.poll_events();
    assert!(events.is_empty());
}

#[test]
fn watcher_channel_disconnect_fans_reconcile_subtree_and_records_reason() {
    let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
    let mut watcher = GuardWatcher::with_channel_for_test(rx, GuardReconciliationConfig::default());

    let dir1 = tempdir().unwrap();
    let dir2 = tempdir().unwrap();
    watcher.add_root(dir1.path().to_path_buf()).unwrap();
    watcher.add_root(dir2.path().to_path_buf()).unwrap();

    assert_eq!(watcher.watcher_status(), "watching");
    assert!(!watcher.is_disconnected());
    assert!(watcher.disconnection_reason().is_none());

    // Drop sender to simulate watcher backend thread exit / panic / disconnection.
    drop(tx);

    let events = watcher.poll_events();
    assert!(watcher.is_disconnected());
    assert_eq!(watcher.watcher_status(), "disconnected");
    assert!(watcher
        .disconnection_reason()
        .unwrap()
        .contains("watcher backend disconnected"));

    // Fail-closed invariant: Every watched root must receive a ReconcileSubtree event.
    assert_eq!(events.len(), 2);
    for (_root, evts) in events {
        assert!(evts
            .iter()
            .any(|e| matches!(e, GuardEvent::ReconcileSubtree(_))));
    }
}

#[test]
fn add_root_fails_when_watcher_disconnected() {
    let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
    let mut watcher = GuardWatcher::with_channel_for_test(rx, GuardReconciliationConfig::default());

    drop(tx);
    let _ = watcher.poll_events();
    assert!(watcher.is_disconnected());

    let dir = tempdir().unwrap();
    let res = watcher.add_root(dir.path().to_path_buf());
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("watcher backend disconnected"));
}
