//! WHY: Closes defect class where guard filesystem watcher generated unnecessary
//! reconcile transactions and transitioned roots out of Current on events inside
//! ignored or excluded paths (.git, target, node_modules, ignore_paths, and default
//! excludes) (Row 141).
//!
//! The guard watcher is advisory and must mirror scan path semantics: changes to
//! repository metadata (.git), build output (target, dist, build, out), dependency
//! trees (node_modules, vendor, .venv), package manager lockfiles, minified bundles,
//! backup/temp files, binary/media extensions, and operator-configured ignore_paths
//! must be filtered out at the watcher boundary rather than polluting the event
//! buffer and triggering spurious dirty reconciliation loops.
//!
//! WHAT THIS DOES NOT CATCH:
//! OS-level filesystem watcher event drop when kernel inotify queue limits are exhausted
//! before delivery to the user-space process (handled by overflow ReconcileSubtree).

#![cfg(unix)]

use keyhog::testing::daemon::guard_runtime::GuardRuntime;
use keyhog::testing::daemon::guard_watcher::GuardWatcher;
use keyhog::testing::daemon::server::{guard_event_action, GuardEventAction};
use keyhog_core::guard_state::{
    FilesystemAuthority, FilesystemIdentity, GuardRootMode, GuardRootState, GuardTransition,
};
use keyhog_sources::guard::{GuardEvent, GuardReconciliationConfig};
use notify::event::{CreateKind, ModifyKind};
use notify::EventKind;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

fn test_fs_identity() -> FilesystemIdentity {
    FilesystemIdentity {
        device: 1,
        inode: 42,
    }
}

fn test_fs_authority() -> FilesystemAuthority {
    FilesystemAuthority::authoritative("ext4")
}

#[test]
fn git_directory_events_ignored_by_guard_watcher() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root = PathBuf::from("/srv/repo");
    watcher.add_root(root.clone()).expect("add root");

    let git_paths = vec![
        root.join(".git/index"),
        root.join(".git/HEAD"),
        root.join(".git/objects/4b/825dc642cb6eb9a060e54bf8d69288fbee4904"),
        root.join(".git/refs/heads/main"),
        root.join(".git/COMMIT_EDITMSG"),
        root.join(".git/FETCH_HEAD"),
        root.join(".git/logs/HEAD"),
    ];

    for path in git_paths {
        assert!(
            watcher.is_path_excluded(&root, &path),
            "path {} must be excluded",
            path.display()
        );
        let mut event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
        event.paths.push(path);
        tx.send(Ok(event)).expect("send event");
    }

    let polled = watcher.poll_events();
    assert!(
        polled.is_empty(),
        "watcher must emit zero events for changes inside .git"
    );
    assert_eq!(watcher.pending_event_count(&root), 0);
}

#[test]
fn target_directory_events_ignored_by_guard_watcher() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root = PathBuf::from("/srv/workspace");
    watcher.add_root(root.clone()).expect("add root");

    let target_paths = vec![
        root.join("target/debug/app"),
        root.join("target/debug/deps/libkeyhog.rlib"),
        root.join("target/release/build/foo.o"),
        root.join("target/CACHEDIR.TAG"),
        root.join("target/.rustc_info.json"),
    ];

    for path in target_paths {
        assert!(
            watcher.is_path_excluded(&root, &path),
            "target path {} must be excluded",
            path.display()
        );
        let mut event = notify::Event::new(EventKind::Create(CreateKind::File));
        event.paths.push(path);
        tx.send(Ok(event)).expect("send event");
    }

    let polled = watcher.poll_events();
    assert!(
        polled.is_empty(),
        "watcher must emit zero events for build output inside target/"
    );
    assert_eq!(watcher.pending_event_count(&root), 0);
}

#[test]
fn node_modules_directory_events_ignored_by_guard_watcher() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root = PathBuf::from("/srv/web_app");
    watcher.add_root(root.clone()).expect("add root");

    let node_modules_paths = vec![
        root.join("node_modules/express/index.js"),
        root.join("node_modules/lodash/package.json"),
        root.join("packages/frontend/node_modules/react/index.js"),
        root.join("node_modules/.bin/tsc"),
    ];

    for path in node_modules_paths {
        assert!(
            watcher.is_path_excluded(&root, &path),
            "node_modules path {} must be excluded",
            path.display()
        );
        let mut event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
        event.paths.push(path);
        tx.send(Ok(event)).expect("send event");
    }

    let polled = watcher.poll_events();
    assert!(
        polled.is_empty(),
        "watcher must emit zero events for dependency files inside node_modules/"
    );
    assert_eq!(watcher.pending_event_count(&root), 0);
}

#[test]
fn runtime_derived_default_exclude_dirs_all_filtered() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root = PathBuf::from("/srv/project");
    watcher.add_root(root.clone()).expect("add root");

    // Derived dynamically from source default excludes schema.
    let default_dirs = keyhog_sources::default_exclude_dir_components();
    assert!(
        !default_dirs.is_empty(),
        "source default exclude dirs must not be empty"
    );

    for dir_name in default_dirs {
        let path = root.join(dir_name).join("file.txt");
        assert!(
            watcher.is_path_excluded(&root, &path),
            "derived default directory component '{}' must be excluded by guard watcher",
            dir_name
        );
        let mut event = notify::Event::new(EventKind::Create(CreateKind::File));
        event.paths.push(path);
        tx.send(Ok(event)).expect("send event");
    }

    let polled = watcher.poll_events();
    assert!(
        polled.is_empty(),
        "watcher must emit zero events for any source-owned default exclude directory"
    );
}

#[test]
fn default_excluded_files_and_suffixes_filtered() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root = PathBuf::from("/srv/repo");
    watcher.add_root(root.clone()).expect("add root");

    let excluded_files = vec![
        // Lockfiles
        root.join("package-lock.json"),
        root.join("yarn.lock"),
        root.join("pnpm-lock.yaml"),
        root.join("Cargo.lock"),
        root.join("go.sum"),
        root.join("poetry.lock"),
        root.join("Pipfile.lock"),
        root.join("composer.lock"),
        // Infixes
        root.join("src/app.min.js"),
        root.join("src/styles.bundle.css"),
        // Suffixes
        root.join("src/main.rs.bak"),
        root.join("src/main.rs.tmp"),
        root.join("src/main.rs.swp"),
        root.join("dist/bundle.js.map"),
        // TSConfig prefix-suffix
        root.join("tsconfig.build.json"),
        root.join("cache.json"),
        root.join("angular.json"),
    ];

    for path in &excluded_files {
        assert!(
            watcher.is_path_excluded(&root, path),
            "file {} must be excluded by default scan semantics",
            path.display()
        );
        let mut event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
        event.paths.push(path.clone());
        tx.send(Ok(event)).expect("send event");
    }

    let polled = watcher.poll_events();
    assert!(
        polled.is_empty(),
        "watcher must emit zero events for default excluded files, lockfiles, and minified bundles"
    );
}

#[test]
fn cargo_credentials_not_excluded_by_watcher() {
    // WHY: the watcher must mirror scanner traversal truth. The scanner's
    // default excludes prune no `.cargo` component and skip no `.toml`
    // filename, so `.cargo/credentials.toml` is a scanned leak vector and
    // its events must reach the guard.
    //
    // Extension-based filtering (png, jpg, etc.) happens at the reader pool,
    // not the watcher path classifier, so media files ARE delivered as events
    // even though scans ultimately skip them by extension.
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root = PathBuf::from("/srv/repo");
    watcher.add_root(root.clone()).expect("add root");

    assert!(
        !watcher.is_path_excluded(&root, &root.join(".cargo/credentials.toml")),
        "scanned path .cargo/credentials.toml must NOT be excluded by watcher"
    );
    // Images are NOT excluded at the watcher level (extension denylist feeds
    // the reader, not the path classifier) so they produce events.
    assert!(
        !watcher.is_path_excluded(&root, &root.join("assets/logo.png")),
        "image extension png is not a watcher-level exclusion"
    );

    for path in [".cargo/credentials.toml", "src/main.rs", "assets/logo.png"] {
        let mut event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
        event.paths.push(root.join(path));
        tx.send(Ok(event)).expect("send event");
    }

    let polled = watcher.poll_events();
    assert_eq!(
        polled.len(),
        1,
        "watcher must emit all non-excluded file events to the root"
    );
}

#[test]
fn explicit_ignore_paths_filtered_by_guard_watcher() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root = PathBuf::from("/srv/custom_app");
    let ignore_paths = vec![
        "generated/**".to_string(),
        "*.log".to_string(),
        "temp_data/*".to_string(),
    ];
    watcher
        .add_root_with_exclusions(root.clone(), ignore_paths, true)
        .expect("add root with exclusions");

    let ignored = vec![
        root.join("generated/client/api.ts"),
        root.join("server.log"),
        root.join("debug.log"),
        root.join("temp_data/scratch.json"),
    ];

    for path in &ignored {
        assert!(
            watcher.is_path_excluded(&root, path),
            "custom ignored path {} must be excluded",
            path.display()
        );
        let mut event = notify::Event::new(EventKind::Create(CreateKind::File));
        event.paths.push(path.clone());
        tx.send(Ok(event)).expect("send event");
    }

    let polled = watcher.poll_events();
    assert!(
        polled.is_empty(),
        "watcher must emit zero events for explicit ignore_paths"
    );

    // Valid non-ignored file in same root MUST produce event
    let valid_file = root.join("src/handler.rs");
    assert!(!watcher.is_path_excluded(&root, &valid_file));
    let mut valid_event = notify::Event::new(EventKind::Create(CreateKind::File));
    valid_event.paths.push(valid_file.clone());
    tx.send(Ok(valid_event)).expect("send valid event");

    let polled = watcher.poll_events();
    let map: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();
    assert_eq!(map.len(), 1);
    assert_eq!(
        map.get(&root).unwrap(),
        &vec![GuardEvent::Create(valid_file)]
    );
}

#[test]
fn root_keyhogignore_and_gitignore_honored() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    // Create .keyhogignore and .gitignore in the root
    fs::write(root.join(".keyhogignore"), "fixtures_secret/**\n*.local\n").unwrap();
    fs::write(root.join(".gitignore"), "build_out/\n*.tmp_log\n").unwrap();

    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);
    watcher.add_root(root.clone()).expect("add root");

    let ignored = vec![
        root.join("fixtures_secret/test_key.json"),
        root.join("config.local"),
        root.join("build_out/artifact.bin"),
        root.join("app.tmp_log"),
    ];

    for path in &ignored {
        assert!(
            watcher.is_path_excluded(&root, path),
            "path {} matching .keyhogignore/.gitignore must be excluded",
            path.display()
        );
        let mut event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
        event.paths.push(path.clone());
        tx.send(Ok(event)).expect("send event");
    }

    let polled = watcher.poll_events();
    assert!(
        polled.is_empty(),
        "watcher must honor .keyhogignore and .gitignore rules in root"
    );

    // Legitimate code file produces event
    let code_file = root.join("src/lib.rs");
    assert!(!watcher.is_path_excluded(&root, &code_file));
    let mut code_event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
    code_event.paths.push(code_file.clone());
    tx.send(Ok(code_event)).expect("send code event");

    let polled = watcher.poll_events();
    let map: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();
    assert_eq!(map.len(), 1);
    assert_eq!(
        map.get(&root).unwrap(),
        &vec![GuardEvent::Modify(code_file)]
    );
}

#[test]
fn mixed_batch_event_filters_excluded_and_retains_valid_paths() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root = PathBuf::from("/srv/mixed_app");
    watcher.add_root(root.clone()).expect("add root");

    let git_file = root.join(".git/COMMIT_EDITMSG");
    let target_file = root.join("target/debug/build.o");
    let node_modules_file = root.join("node_modules/chalk/index.js");
    let lockfile = root.join("Cargo.lock");
    let valid_file_1 = root.join("src/main.rs");
    let valid_file_2 = root.join("src/auth/token.rs");

    let mut batch_event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
    batch_event.paths.push(git_file);
    batch_event.paths.push(valid_file_1.clone());
    batch_event.paths.push(target_file);
    batch_event.paths.push(node_modules_file);
    batch_event.paths.push(lockfile);
    batch_event.paths.push(valid_file_2.clone());

    tx.send(Ok(batch_event)).expect("send mixed batch event");

    let polled = watcher.poll_events();
    let map: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();
    assert_eq!(map.len(), 1);
    let events = map.get(&root).expect("root events");
    assert_eq!(
        events,
        &vec![
            GuardEvent::Modify(valid_file_1),
            GuardEvent::Modify(valid_file_2),
        ],
        "only non-excluded paths must be queued in sequence"
    );
}

#[test]
fn no_default_excludes_toggle_admits_default_excluded_paths() {
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root = PathBuf::from("/srv/unfiltered_app");
    // respect_default_excludes = false
    watcher
        .add_root_with_exclusions(root.clone(), Vec::new(), false)
        .expect("add root without default excludes");

    let lockfile = root.join("Cargo.lock");
    assert!(
        !watcher.is_path_excluded(&root, &lockfile),
        "Cargo.lock must not be excluded when respect_default_excludes is false"
    );

    let mut event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
    event.paths.push(lockfile.clone());
    tx.send(Ok(event)).expect("send event");

    let polled = watcher.poll_events();
    let map: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();
    assert_eq!(map.len(), 1);
    assert_eq!(map.get(&root).unwrap(), &vec![GuardEvent::Modify(lockfile)]);
}

#[test]
fn acceptance_excluded_events_do_not_generate_reconcile_transactions() {
    // Acceptance criterion: Watcher ignores events inside excluded directories
    // without generating unnecessary reconcile transactions.
    let rt = GuardRuntime::new();
    let root_path = b"/srv/acceptance_repo".to_vec();
    let root_pathbuf = PathBuf::from("/srv/acceptance_repo");

    rt.add_root(
        root_path.clone(),
        test_fs_identity(),
        test_fs_authority(),
        GuardRootMode::Repo,
    )
    .expect("add root to runtime");

    // Transition Stopped -> Indexing -> Current
    rt.transition_root(&root_path, &GuardTransition::ReconciliationStarted)
        .expect("transition to indexing");
    rt.transition_root(&root_path, &GuardTransition::ReconciliationClean)
        .expect("transition to current");
    assert_eq!(rt.root_state(&root_path), Some(GuardRootState::Current));
    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);
    watcher.add_root(root_pathbuf.clone()).expect("add root");

    // 1. Simulate barrage of events in excluded directories (.git, target, node_modules)
    let excluded_events = vec![
        root_pathbuf.join(".git/index"),
        root_pathbuf.join(".git/HEAD"),
        root_pathbuf.join("target/debug/incremental/123"),
        root_pathbuf.join("node_modules/pkg/lib.js"),
        root_pathbuf.join("package-lock.json"),
        root_pathbuf.join("dist/bundle.js.map"),
    ];

    for path in excluded_events {
        let mut event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
        event.paths.push(path);
        tx.send(Ok(event)).expect("send excluded event");
    }

    // Poll events from watcher
    let polled = watcher.poll_events();
    assert!(
        polled.is_empty(),
        "watcher must ignore all excluded directory and file events"
    );

    // Process polled events through server guard state machine
    for (root, evts) in polled {
        let root_bytes = root.as_os_str().as_encoded_bytes();
        let has_overflow = evts
            .iter()
            .any(|e| matches!(e, GuardEvent::ReconcileSubtree(_)));
        let current_state = rt.root_state(root_bytes);
        if let GuardEventAction::Transition(transition) =
            guard_event_action(current_state, has_overflow)
        {
            let _ = rt.transition_root(root_bytes, &transition);
        }
    }

    // Invariant: Root state remains Current without triggering reconcile transaction
    assert_eq!(
        rt.root_state(&root_path),
        Some(GuardRootState::Current),
        "root state MUST remain Current after events inside excluded directories (.git, target, node_modules)"
    );

    // 2. Now simulate a modification to an actual tracked source file
    let tracked_source = root_pathbuf.join("src/lib.rs");
    let mut real_event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
    real_event.paths.push(tracked_source.clone());
    tx.send(Ok(real_event)).expect("send real source event");

    let polled = watcher.poll_events();
    assert_eq!(polled.len(), 1);

    for (root, evts) in polled {
        let root_bytes = root.as_os_str().as_encoded_bytes();
        let has_overflow = evts
            .iter()
            .any(|e| matches!(e, GuardEvent::ReconcileSubtree(_)));
        let current_state = rt.root_state(root_bytes);
        if let GuardEventAction::Transition(transition) =
            guard_event_action(current_state, has_overflow)
        {
            let _ = rt.transition_root(root_bytes, &transition);
        }
    }

    // Invariant: Legitimate file modification transitions root to Dirty (EventAccepted)
    assert_eq!(
        rt.root_state(&root_path),
        Some(GuardRootState::Dirty),
        "root state MUST transition to Dirty when a legitimate non-excluded source file changes"
    );
}

#[test]
fn mutation_gate_detects_unfiltered_exclusion_regressions() {
    // Prove that the filter distinguishes excluded paths from non-excluded paths.

    let mut watcher = GuardWatcher::new_disabled();
    let root = PathBuf::from("/srv/mutation_repo");
    watcher.add_root(root.clone()).expect("add root");

    // Positive exclusions (must be true)
    assert!(watcher.is_path_excluded(&root, &root.join(".git")));
    assert!(watcher.is_path_excluded(&root, &root.join(".git/index")));
    assert!(watcher.is_path_excluded(&root, &root.join("target")));
    assert!(watcher.is_path_excluded(&root, &root.join("target/debug/foo")));
    assert!(watcher.is_path_excluded(&root, &root.join("node_modules")));
    assert!(watcher.is_path_excluded(&root, &root.join("node_modules/foo/bar.js")));
    assert!(watcher.is_path_excluded(&root, &root.join("Cargo.lock")));
    assert!(watcher.is_path_excluded(&root, &root.join("package-lock.json")));
    assert!(watcher.is_path_excluded(&root, &root.join("app.min.js")));
    assert!(watcher.is_path_excluded(&root, &root.join("file.bak")));
    assert!(watcher.is_path_excluded(&root, &root.join("bundle.js.map")));

    // Negative exclusions (must NOT be excluded)
    assert!(!watcher.is_path_excluded(&root, &root.join("logo.png")));
    // Negative exclusions (must NOT be excluded)
    assert!(!watcher.is_path_excluded(&root, &root.join("src/main.rs")));
    assert!(!watcher.is_path_excluded(&root, &root.join("src/git_helper.rs")));
    assert!(!watcher.is_path_excluded(&root, &root.join("src/targeted_search.rs")));
    assert!(!watcher.is_path_excluded(&root, &root.join("src/node_types.rs")));
    assert!(!watcher.is_path_excluded(&root, &root.join("Cargo.toml")));
    assert!(!watcher.is_path_excluded(&root, &root.join("package.json")));
    assert!(!watcher.is_path_excluded(&root, &root.join("README.md")));
}

#[test]
fn dot_keyhog_toml_scan_exclude_applied_on_add_root() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    let config_content = r#"
[scan]
exclude = ["custom_excluded/**", "*.secret.txt"]
"#;
    fs::write(root.join(".keyhog.toml"), config_content).expect("write .keyhog.toml");

    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);
    watcher.add_root(root.clone()).expect("add root");

    assert_eq!(
        &watcher.root_ignore_paths(&root).unwrap()[..],
        &["custom_excluded/**", "*.secret.txt"]
    );

    assert!(watcher.is_path_excluded(&root, &root.join("custom_excluded/data.json")));
    assert!(watcher.is_path_excluded(&root, &root.join("test.secret.txt")));
    assert!(!watcher.is_path_excluded(&root, &root.join("src/lib.rs")));

    let mut event = notify::Event::new(EventKind::Create(CreateKind::File));
    event.paths.push(root.join("custom_excluded/data.json"));
    event.paths.push(root.join("src/lib.rs"));
    tx.send(Ok(event)).expect("send event");

    let polled = watcher.poll_events();
    let map: HashMap<PathBuf, Vec<GuardEvent>> = polled.into_iter().collect();
    assert_eq!(map.len(), 1);
    assert_eq!(
        map.get(&root).unwrap(),
        &vec![GuardEvent::Create(root.join("src/lib.rs"))]
    );
}

#[test]
fn ignore_matcher_dynamic_reload_on_gitignore_change() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();

    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);
    watcher.add_root(root.clone()).expect("add root");

    let ignored_target = root.join("dynamically_ignored.txt");
    assert!(!watcher.is_path_excluded(&root, &ignored_target));

    // Create .gitignore
    let gitignore_path = root.join(".gitignore");
    fs::write(&gitignore_path, "dynamically_ignored.txt\n").expect("write .gitignore");

    // Send notify event for .gitignore change
    let mut gi_event = notify::Event::new(EventKind::Create(CreateKind::File));
    gi_event.paths.push(gitignore_path.clone());
    tx.send(Ok(gi_event)).expect("send gitignore create");

    // Poll events so maybe_reload_ignore_matcher executes
    let _ = watcher.poll_events();

    // Now the path must be excluded!
    assert!(watcher.is_path_excluded(&root, &ignored_target));

    // Send event on the newly ignored file - must be filtered
    let mut ign_event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
    ign_event.paths.push(ignored_target);
    tx.send(Ok(ign_event)).expect("send ignored event");

    let polled = watcher.poll_events();
    assert!(
        polled.is_empty(),
        "events for newly ignored file must be filtered after dynamic reload"
    );
}

#[test]
fn ignore_matcher_dynamic_reload_on_keyhog_toml_change() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    let config_path = root.join(".keyhog.toml");
    fs::write(&config_path, "[scan]\nexclude = [\"alpha/**\"]\n").expect("write .keyhog.toml");

    let config = GuardReconciliationConfig::default();
    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);
    watcher.add_root(root.clone()).expect("add root");

    assert!(watcher.is_path_excluded(&root, &root.join("alpha/file.txt")));
    assert!(!watcher.is_path_excluded(&root, &root.join("beta/file.txt")));

    // Update .keyhog.toml to exclude beta instead of alpha
    fs::write(&config_path, "[scan]\nexclude = [\"beta/**\"]\n").expect("rewrite .keyhog.toml");

    let mut cfg_event = notify::Event::new(EventKind::Modify(ModifyKind::Any));
    cfg_event.paths.push(config_path.clone());
    tx.send(Ok(cfg_event)).expect("send config modify");

    let _ = watcher.poll_events();

    assert!(!watcher.is_path_excluded(&root, &root.join("alpha/file.txt")));
    assert!(watcher.is_path_excluded(&root, &root.join("beta/file.txt")));
}

#[test]
fn keyhogignore_toml_is_not_treated_as_gitignore_pattern() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    // Write a .keyhogignore.toml with TOML rule suppressor syntax
    let toml_rule_content = r#"
[[rule]]
id = "suppress-test"
paths = ["src/**"]
reason = "test suppression"
"#;
    fs::write(root.join(".keyhogignore.toml"), toml_rule_content)
        .expect("write .keyhogignore.toml");

    let config = GuardReconciliationConfig::default();
    let (mut watcher, _tx) = GuardWatcher::new_with_channel(config);
    watcher.add_root(root.clone()).expect("add root");

    // src/main.rs MUST NOT be excluded by the gitignore matcher
    assert!(
        !watcher.is_path_excluded(&root, &root.join("src/main.rs")),
        ".keyhogignore.toml must not be parsed as gitignore pattern syntax"
    );
}
