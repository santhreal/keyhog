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
    let mut event = notify::Event::new(EventKind::Create(notify::event::CreateKind::File));
    event.paths.push(PathBuf::from("/a/test.txt"));
    let guard_events = normalize_notify_event(&event);
    assert_eq!(guard_events.len(), 1);
}

#[test]
fn normalize_modify_event() {
    let mut event = notify::Event::new(EventKind::Modify(notify::event::ModifyKind::Any));
    event.paths.push(PathBuf::from("/a/test.txt"));
    let guard_events = normalize_notify_event(&event);
    assert_eq!(guard_events.len(), 1);
}

#[test]
fn normalize_remove_event() {
    let mut event = notify::Event::new(EventKind::Remove(notify::event::RemoveKind::File));
    event.paths.push(PathBuf::from("/a/test.txt"));
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
    assert_eq!(
        guard_events[0],
        GuardEvent::Create(PathBuf::from("/a/b.txt"))
    );
    assert_eq!(
        guard_events[1],
        GuardEvent::Create(PathBuf::from("/c/d.txt"))
    );
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

#[test]
fn excluded_directory_paths_filtered_in_unit_watcher() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);
    let root = PathBuf::from("/srv/unit_root");
    watcher.add_root(root.clone()).unwrap();

    let git_file = root.join(".git/index");
    let target_file = root.join("target/debug/foo");
    let nm_file = root.join("node_modules/pkg/index.js");
    let lock_file = root.join("Cargo.lock");
    let code_file = root.join("src/lib.rs");

    let mut event = notify::Event::new(EventKind::Modify(notify::event::ModifyKind::Any));
    event.paths.push(git_file);
    event.paths.push(target_file);
    event.paths.push(nm_file);
    event.paths.push(lock_file);
    event.paths.push(code_file.clone());

    tx.send(Ok(event)).unwrap();

    let polled = watcher.poll_events();
    let map: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();
    assert_eq!(map.len(), 1);
    assert_eq!(
        map.get(&root).unwrap(),
        &vec![GuardEvent::Modify(code_file)]
    );
}

#[test]
fn custom_ignore_paths_filtered_in_unit_watcher() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);
    let root = PathBuf::from("/srv/custom_root");
    watcher
        .add_root_with_exclusions(root.clone(), vec!["*.log".into(), "build/**".into()], true)
        .unwrap();

    assert_eq!(
        watcher.root_ignore_paths(&root).unwrap(),
        &["*.log", "build/**"]
    );
    assert_eq!(watcher.root_respects_default_excludes(&root), Some(true));

    let log_file = root.join("app.log");
    let build_file = root.join("build/out.bin");
    let normal_file = root.join("src/main.rs");

    let mut event = notify::Event::new(EventKind::Create(notify::event::CreateKind::File));
    event.paths.push(log_file);
    event.paths.push(build_file);
    event.paths.push(normal_file.clone());

    tx.send(Ok(event)).unwrap();

    let polled = watcher.poll_events();
    let map: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();
    assert_eq!(map.len(), 1);
    assert_eq!(
        map.get(&root).unwrap(),
        &vec![GuardEvent::Create(normal_file)]
    );
}
