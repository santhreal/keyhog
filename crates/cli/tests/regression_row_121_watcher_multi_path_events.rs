//! WHY: Closes defect class where filesystem watcher events only attributed the first path
//! in `event.paths`, silently dropping secondary paths during cross-root moves/renames and
//! silently dropping empty-path fidelity loss / rescan signals (Row 121).
//!
//! WHAT THIS DOES NOT CATCH:
//! Kernel-level inotify queue drops occurring before notification delivery to the process.

#![cfg(unix)]

use keyhog::daemon::guard_watcher::{normalize_notify_event, GuardWatcher};
use keyhog_sources::guard::{GuardEvent, GuardReconciliationConfig};
use notify::event::{CreateKind, ModifyKind, RemoveKind, RenameMode};
use notify::EventKind;
use std::collections::HashMap;
use std::path::PathBuf;

#[test]
fn multi_path_events_attributed_to_distinct_roots() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root_a = PathBuf::from("/srv/repo_alpha");
    let root_b = PathBuf::from("/srv/repo_beta");
    watcher.add_root(root_a.clone()).expect("add root_a");
    watcher.add_root(root_b.clone()).expect("add root_b");

    // Simulate cross-root move/rename event carrying [source_path, dest_path]
    let from_path = root_a.join("src/secrets_alpha.rs");
    let to_path = root_b.join("src/secrets_beta.rs");

    let mut rename_event = notify::Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)));
    rename_event.paths.push(from_path.clone());
    rename_event.paths.push(to_path.clone());

    tx.send(Ok(rename_event)).expect("send rename event");

    let polled = watcher.poll_events();
    let results: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();

    assert_eq!(
        results.len(),
        2,
        "both source and destination roots must receive attributed events"
    );

    let events_a = results.get(&root_a).expect("root_a events");
    assert_eq!(
        events_a,
        &vec![GuardEvent::Modify(from_path)],
        "root_a must receive event for source path"
    );

    let events_b = results.get(&root_b).expect("root_b events");
    assert_eq!(
        events_b,
        &vec![GuardEvent::Modify(to_path)],
        "root_b must receive event for destination path"
    );
}

#[test]
fn multi_path_events_within_same_root() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root = PathBuf::from("/srv/repo_gamma");
    watcher.add_root(root.clone()).expect("add root");

    let file_1 = root.join("src/f1.rs");
    let file_2 = root.join("src/f2.rs");
    let file_3 = root.join("src/f3.rs");

    let mut batch_event = notify::Event::new(EventKind::Create(CreateKind::File));
    batch_event.paths.push(file_1.clone());
    batch_event.paths.push(file_2.clone());
    batch_event.paths.push(file_3.clone());

    tx.send(Ok(batch_event)).expect("send batch create event");

    let polled = watcher.poll_events();
    let results: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();

    assert_eq!(results.len(), 1);
    let events = results.get(&root).expect("root events");
    assert_eq!(
        events,
        &vec![
            GuardEvent::Create(file_1),
            GuardEvent::Create(file_2),
            GuardEvent::Create(file_3),
        ],
        "all paths in single-root batch must be queued in sequence order"
    );
}

#[test]
fn multi_path_events_with_unwatched_paths_safely_ignored() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root_a = PathBuf::from("/srv/watched_a");
    let root_b = PathBuf::from("/srv/watched_b");
    watcher.add_root(root_a.clone()).expect("add root_a");
    watcher.add_root(root_b.clone()).expect("add root_b");

    let file_a = root_a.join("config.json");
    let file_unwatched = PathBuf::from("/var/log/syslog");
    let file_b = root_b.join("app.log");

    let mut event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
    event.paths.push(file_a.clone());
    event.paths.push(file_unwatched);
    event.paths.push(file_b.clone());

    tx.send(Ok(event)).expect("send event with unwatched paths");

    let polled = watcher.poll_events();
    let results: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();

    assert_eq!(results.len(), 2, "only watched roots should be present");
    assert_eq!(results.get(&root_a).unwrap(), &vec![GuardEvent::Modify(file_a)]);
    assert_eq!(results.get(&root_b).unwrap(), &vec![GuardEvent::Modify(file_b)]);
}

#[test]
fn empty_paths_vector_triggers_subtree_reconciliation_across_all_roots() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let roots: Vec<PathBuf> = (1..=5)
        .map(|i| PathBuf::from(format!("/srv/repo_{}", i)))
        .collect();

    for r in &roots {
        watcher.add_root(r.clone()).expect("add root");
    }

    // Send empty-paths event (e.g. bulk kernel notify signal / rescan trigger)
    let empty_event = notify::Event::new(EventKind::Other);
    assert!(empty_event.paths.is_empty());
    tx.send(Ok(empty_event)).expect("send empty paths event");

    let polled = watcher.poll_events();
    let results: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();

    assert_eq!(
        results.len(),
        roots.len(),
        "every watched root must receive a ReconcileSubtree event"
    );

    for r in &roots {
        let evts = results.get(r).expect("events for root");
        assert_eq!(
            evts,
            &vec![GuardEvent::ReconcileSubtree(r.clone())],
            "root {} must be flagged for subtree reconciliation",
            r.display()
        );
    }
}

#[test]
fn empty_paths_vector_with_zero_roots_is_safe_noop() {
    let config = GuardReconciliationConfig::default();
    let (watcher, tx) = GuardWatcher::new_with_channel(config);
    assert_eq!(watcher.root_count(), 0);

    let empty_event = notify::Event::new(EventKind::Other);
    tx.send(Ok(empty_event)).expect("send empty event");

    let polled = watcher.poll_events();
    assert!(
        polled.is_empty(),
        "empty paths event with zero roots must return empty without panic"
    );
}

#[test]
fn normalize_notify_event_multi_path_totality() {
    // 1. Create event with multiple paths
    let mut create_event = notify::Event::new(EventKind::Create(CreateKind::File));
    create_event.paths.push(PathBuf::from("/a/1.txt"));
    create_event.paths.push(PathBuf::from("/b/2.txt"));
    let normalized = normalize_notify_event(&create_event);
    assert_eq!(normalized.len(), 2);
    assert_eq!(normalized[0], GuardEvent::Create(PathBuf::from("/a/1.txt")));
    assert_eq!(normalized[1], GuardEvent::Create(PathBuf::from("/b/2.txt")));

    // 2. Remove event with multiple paths
    let mut remove_event = notify::Event::new(EventKind::Remove(RemoveKind::File));
    remove_event.paths.push(PathBuf::from("/a/1.txt"));
    remove_event.paths.push(PathBuf::from("/b/2.txt"));
    let normalized = normalize_notify_event(&remove_event);
    assert_eq!(normalized.len(), 2);
    assert_eq!(normalized[0], GuardEvent::Remove(PathBuf::from("/a/1.txt")));
    assert_eq!(normalized[1], GuardEvent::Remove(PathBuf::from("/b/2.txt")));

    // 3. Modify event with multiple paths
    let mut modify_event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
    modify_event.paths.push(PathBuf::from("/a/1.txt"));
    modify_event.paths.push(PathBuf::from("/b/2.txt"));
    let normalized = normalize_notify_event(&modify_event);
    assert_eq!(normalized.len(), 2);
    assert_eq!(normalized[0], GuardEvent::Modify(PathBuf::from("/a/1.txt")));
    assert_eq!(normalized[1], GuardEvent::Modify(PathBuf::from("/b/2.txt")));

    // 4. Other/Generic event with multiple paths
    let mut other_event = notify::Event::new(EventKind::Other);
    other_event.paths.push(PathBuf::from("/a/1.txt"));
    let normalized = normalize_notify_event(&other_event);
    assert_eq!(normalized.len(), 1);
    assert_eq!(normalized[0], GuardEvent::Modify(PathBuf::from("/a/1.txt")));

    // 5. Empty paths event normalization
    let empty_create = notify::Event::new(EventKind::Create(CreateKind::File));
    let normalized = normalize_notify_event(&empty_create);
    assert_eq!(normalized.len(), 1);
    assert_eq!(normalized[0], GuardEvent::Create(PathBuf::from("")));
}

#[test]
fn nested_roots_multi_prefix_attribution() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let parent_root = PathBuf::from("/srv/workspace");
    let nested_root = PathBuf::from("/srv/workspace/sub_project");

    watcher.add_root(parent_root.clone()).expect("add parent root");
    watcher.add_root(nested_root.clone()).expect("add nested root");

    let parent_file = parent_root.join("root_file.rs");
    let nested_file = nested_root.join("nested_file.rs");

    let mut event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
    event.paths.push(parent_file.clone());
    event.paths.push(nested_file.clone());

    tx.send(Ok(event)).expect("send event");

    let polled = watcher.poll_events();
    let results: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();

    assert_eq!(results.len(), 2);
    // Parent root receives events for both parent_file and nested_file
    assert_eq!(
        results.get(&parent_root).unwrap(),
        &vec![GuardEvent::Modify(parent_file), GuardEvent::Modify(nested_file.clone())]
    );
    // Nested root receives event for nested_file
    assert_eq!(
        results.get(&nested_root).unwrap(),
        &vec![GuardEvent::Modify(nested_file)]
    );
}

#[test]
fn interleaved_empty_and_concrete_events_preservation() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root_a = PathBuf::from("/srv/root_a");
    let root_b = PathBuf::from("/srv/root_b");
    watcher.add_root(root_a.clone()).expect("add root_a");
    watcher.add_root(root_b.clone()).expect("add root_b");

    // 1. Concrete event on root_a
    let file_a = root_a.join("main.rs");
    let mut evt1 = notify::Event::new(EventKind::Create(CreateKind::File));
    evt1.paths.push(file_a.clone());
    tx.send(Ok(evt1)).expect("send evt1");

    // 2. Empty paths fidelity-loss signal
    let evt2 = notify::Event::new(EventKind::Other);
    tx.send(Ok(evt2)).expect("send evt2");

    let polled = watcher.poll_events();
    let results: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();

    assert_eq!(results.len(), 2);
    // Root A should have both ReconcileSubtree and Create
    let evts_a = results.get(&root_a).expect("evts_a");
    assert!(
        evts_a.contains(&GuardEvent::ReconcileSubtree(root_a.clone())),
        "root_a must have reconcile event"
    );
    assert!(
        evts_a.contains(&GuardEvent::Create(file_a)),
        "root_a must have create event"
    );

    // Root B should have ReconcileSubtree
    let evts_b = results.get(&root_b).expect("evts_b");
    assert_eq!(
        evts_b,
        &vec![GuardEvent::ReconcileSubtree(root_b)],
        "root_b must have reconcile event"
    );
}
