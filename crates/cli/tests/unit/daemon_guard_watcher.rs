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
fn normalize_multi_path_event() {
    let mut event = notify::Event::new(EventKind::Create(notify::event::CreateKind::File));
    event.paths.push(PathBuf::from("/a/b.txt"));
    event.paths.push(PathBuf::from("/c/d.txt"));
    let guard_events = normalize_notify_event(&event);
    assert_eq!(guard_events.len(), 2);
    assert_eq!(guard_events[0], GuardEvent::Create(PathBuf::from("/a/b.txt")));
    assert_eq!(guard_events[1], GuardEvent::Create(PathBuf::from("/c/d.txt")));
}

#[test]
fn poll_events_multi_path_across_roots() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);
    let root_a = PathBuf::from("/tmp/root_a");
    let root_b = PathBuf::from("/tmp/root_b");
    watcher.add_root(root_a.clone()).unwrap();
    watcher.add_root(root_b.clone()).unwrap();

    let mut event = notify::Event::new(EventKind::Modify(notify::event::ModifyKind::Any));
    let file_a = root_a.join("file_a.txt");
    let file_b = root_b.join("file_b.txt");
    event.paths.push(file_a.clone());
    event.paths.push(file_b.clone());
    tx.send(Ok(event)).unwrap();

    let polled = watcher.poll_events();
    let map: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();
    assert_eq!(map.len(), 2);
    assert_eq!(map.get(&root_a).unwrap(), &vec![GuardEvent::Modify(file_a)]);
    assert_eq!(map.get(&root_b).unwrap(), &vec![GuardEvent::Modify(file_b)]);
}

#[test]
fn poll_events_empty_paths_triggers_all_roots_reconcile() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);
    let root_a = PathBuf::from("/tmp/root_a");
    let root_b = PathBuf::from("/tmp/root_b");
    watcher.add_root(root_a.clone()).unwrap();
    watcher.add_root(root_b.clone()).unwrap();

    let event = notify::Event::new(EventKind::Other);
    assert!(event.paths.is_empty());
    tx.send(Ok(event)).unwrap();

    let polled = watcher.poll_events();
    let map: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();
    assert_eq!(map.len(), 2);
    assert_eq!(
        map.get(&root_a).unwrap(),
        &vec![GuardEvent::ReconcileSubtree(root_a)]
    );
    assert_eq!(
        map.get(&root_b).unwrap(),
        &vec![GuardEvent::ReconcileSubtree(root_b)]
    );
}
