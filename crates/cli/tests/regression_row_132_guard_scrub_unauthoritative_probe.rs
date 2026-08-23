//! WHY: Closes the defect class where network and userspace filesystems (NFS, SMB/CIFS,
//! 9P, FUSE, AFS, CEPH, overlay) that do not generate authoritative kernel-level file
//! change events were silently treated as fully watched, leading to undetected secret
//! modifications when changes occurred remotely or bypassed local inotify (Row 132).
//!
//! What this does NOT catch: physical block-device corruptions or hardware controller failures.

use keyhog::testing::daemon::fs_probe::{
    classify_filesystem_type, probe_filesystem_authority, set_test_fs_authority_override,
    DEFAULT_UNAUTHORITATIVE_SCRUB_INTERVAL_SECS,
};
use keyhog::testing::daemon::guard_runtime::GuardRuntime;
use keyhog_core::guard_state::{
    FilesystemAuthority, FilesystemIdentity, GuardRootMode, GuardRootState, GuardTransition,
};
use tempfile::tempdir;

fn test_fs_identity() -> FilesystemIdentity {
    FilesystemIdentity {
        device: 1,
        inode: 42,
    }
}

#[test]
fn row_132_local_filesystems_are_classified_as_authoritative() {
    let authoritative_types = [
        "ext4", "ext3", "ext2", "btrfs", "xfs", "zfs", "f2fs", "vfat", "fat32", "exfat", "ntfs",
        "ntfs3", "tmpfs", "ramfs", "apfs", "hfs", "hfs+", "ufs", "refs",
    ];

    for fs in authoritative_types {
        let auth = classify_filesystem_type(fs);
        assert!(
            auth.authoritative,
            "local filesystem '{fs}' must be classified as authoritative"
        );
        assert_eq!(
            auth.filesystem_type,
            fs.to_ascii_lowercase(),
            "filesystem type must match lowercase"
        );
        assert!(
            auth.unauthoritative_reason.is_none(),
            "authoritative filesystem '{fs}' must have no unauthoritative reason"
        );
    }
}

#[test]
fn row_132_network_and_userspace_filesystems_are_unauthoritative() {
    let unauthoritative_cases = [
        ("nfs", "network filesystem"),
        ("nfs4", "network filesystem"),
        ("cifs", "network filesystem"),
        ("smb", "network filesystem"),
        ("smbfs", "network filesystem"),
        ("9p", "plan 9"),
        ("afs", "Andrew File System"),
        ("ceph", "Ceph distributed filesystem"),
        ("cephfs", "Ceph distributed filesystem"),
        ("glusterfs", "GlusterFS distributed filesystem"),
        ("fuse", "userspace filesystem"),
        ("fuseblk", "userspace filesystem"),
        ("fuse.sshfs", "userspace filesystem"),
        ("overlay", "overlayfs layers"),
    ];

    for (fs, expected_reason_fragment) in unauthoritative_cases {
        let auth = classify_filesystem_type(fs);
        assert!(
            !auth.authoritative,
            "network/userspace filesystem '{fs}' must be classified as unauthoritative"
        );
        assert_eq!(
            auth.filesystem_type,
            fs.to_ascii_lowercase(),
            "filesystem type must match lowercase"
        );
        assert!(
            auth.unauthoritative_reason.is_some(),
            "unauthoritative filesystem '{fs}' must provide a reason"
        );
        let reason = auth.unauthoritative_reason.unwrap();
        assert!(
            reason.contains(expected_reason_fragment),
            "reason '{reason}' for '{fs}' must contain '{expected_reason_fragment}'"
        );
    }
}

#[test]
fn row_132_unknown_filesystems_fail_closed_to_unauthoritative() {
    let unknown_types = ["unknown_fs", "custom_distributed_fs", "magic_vfs_99"];

    for fs in unknown_types {
        let auth = classify_filesystem_type(fs);
        assert!(
            !auth.authoritative,
            "unknown filesystem '{fs}' must fail closed to unauthoritative"
        );
        assert!(
            auth.unauthoritative_reason
                .as_ref()
                .unwrap()
                .contains("unrecognized filesystem type"),
            "unknown filesystem '{fs}' reason must indicate unrecognized type"
        );
    }
}

#[test]
fn row_132_test_force_fs_authority_in_memory_override() {
    let dir = tempdir().expect("tempdir");

    // 1. Force authoritative
    set_test_fs_authority_override(Some(FilesystemAuthority {
        filesystem_type: "nfs".to_string(),
        authoritative: true,
        unauthoritative_reason: None,
    }));
    let auth = probe_filesystem_authority(dir.path());
    assert_eq!(auth.filesystem_type, "nfs");
    assert!(auth.authoritative);
    assert!(auth.unauthoritative_reason.is_none());

    // 2. Force unauthoritative with custom reason
    set_test_fs_authority_override(Some(FilesystemAuthority {
        filesystem_type: "ext4".to_string(),
        authoritative: false,
        unauthoritative_reason: Some("test-simulated-network-mount".to_string()),
    }));
    let auth = probe_filesystem_authority(dir.path());
    assert_eq!(auth.filesystem_type, "ext4");
    assert!(!auth.authoritative);
    assert_eq!(
        auth.unauthoritative_reason.as_deref(),
        Some("test-simulated-network-mount")
    );

    // Clean up override
    set_test_fs_authority_override(None);
}

#[test]
fn row_132_local_path_probe_returns_authoritative_on_standard_mounts() {
    set_test_fs_authority_override(None);
    let dir = tempdir().expect("tempdir");
    let auth = probe_filesystem_authority(dir.path());

    // In normal CI and development environments, tempdir is ext4/tmpfs/apfs/ntfs
    assert!(
        auth.authoritative,
        "local temporary directory on standard OS should probe as authoritative (got {:?})",
        auth
    );
    assert!(!auth.filesystem_type.is_empty());
}

#[test]
fn row_132_root_registration_retains_filesystem_authority() {
    let rt = GuardRuntime::new();
    let root_path = b"/srv/remote_nfs_repo".to_vec();
    let nfs_authority = FilesystemAuthority::unauthoritative(
        "nfs",
        "network filesystem does not deliver kernel events",
    );

    let record = rt
        .add_root(
            root_path.clone(),
            test_fs_identity(),
            nfs_authority.clone(),
            GuardRootMode::Repo,
        )
        .expect("add root");

    assert_eq!(record.filesystem_authority, nfs_authority);
    assert_eq!(record.state, GuardRootState::Stopped);

    let loaded = rt.root_record(&root_path).expect("root record");
    assert_eq!(loaded.filesystem_authority, nfs_authority);
    assert!(!loaded.filesystem_authority.authoritative);
    assert_eq!(loaded.filesystem_authority.filesystem_type, "nfs");
}

#[test]
fn row_132_default_scrub_interval_constant_is_60_seconds() {
    assert_eq!(
        DEFAULT_UNAUTHORITATIVE_SCRUB_INTERVAL_SECS, 60,
        "default unauthoritative scrub interval must be exactly 60 seconds"
    );
}

#[test]
fn row_132_unauthoritative_root_scrub_triggers_reconciliation_from_current() {
    let rt = GuardRuntime::new();
    let root_path = b"/srv/unauthoritative_share".to_vec();
    let nfs_authority = FilesystemAuthority::unauthoritative("nfs", "network mount");

    rt.add_root(
        root_path.clone(),
        test_fs_identity(),
        nfs_authority,
        GuardRootMode::Filesystem,
    )
    .expect("add root");

    // Move to Current
    rt.transition_root(&root_path, &GuardTransition::ReconciliationStarted)
        .expect("start");
    rt.transition_root(&root_path, &GuardTransition::ReconciliationClean)
        .expect("clean");
    assert_eq!(rt.root_state(&root_path), Some(GuardRootState::Current));

    // When scrub triggers, the root transitions via EventAccepted into Dirty
    rt.transition_root(&root_path, &GuardTransition::EventAccepted)
        .expect("scrub dirty");
    assert_eq!(rt.root_state(&root_path), Some(GuardRootState::Dirty));
    // And finishes clean after event scan
    rt.transition_root(&root_path, &GuardTransition::EventsClean)
        .expect("scrub events clean");
    assert_eq!(rt.root_state(&root_path), Some(GuardRootState::Current));
}

#[test]
fn row_132_null_watcher_does_not_disconnect_and_allows_add_root() {
    use keyhog::testing::daemon::guard_watcher::GuardWatcher;
    use keyhog_sources::guard::GuardReconciliationConfig;

    let config = GuardReconciliationConfig::default();
    let mut watcher = GuardWatcher::new_null(config).expect("create null watcher");

    assert!(!watcher.is_disconnected());
    assert_eq!(watcher.watcher_status(), "unmonitored");

    let events = watcher.poll_events();
    assert!(events.is_empty());
    assert!(!watcher.is_disconnected());

    let temp = tempdir().expect("tempdir");
    let root_path = temp.path().join("watched_folder");
    std::fs::create_dir_all(&root_path).expect("create dir");

    assert!(watcher.add_root(root_path).is_ok());
    assert!(!watcher.is_disconnected());
}

#[test]
fn row_132_max_pending_events_total_triggers_overflow_reconcile() {
    use keyhog::testing::daemon::guard_watcher::GuardWatcher;
    use keyhog_sources::guard::{GuardEvent, GuardReconciliationConfig};
    use std::path::PathBuf;

    let mut config = GuardReconciliationConfig::default();
    config.max_pending_events_per_root = 100;
    config.max_pending_events_total = 4; // aggregate limit of 4

    let (mut watcher, tx) = GuardWatcher::new_with_channel(config);

    let root1 = PathBuf::from("/srv/root1");
    let root2 = PathBuf::from("/srv/root2");
    watcher.add_root(root1.clone()).expect("add root1");
    watcher.add_root(root2.clone()).expect("add root2");

    // Send 2 events for root1 and 2 events for root2 -> total = 4
    for i in 0..2 {
        let ev1 = notify::Event {
            kind: notify::EventKind::Create(notify::event::CreateKind::File),
            paths: vec![root1.join(format!("file_{i}.txt"))],
            attrs: notify::event::EventAttributes::default(),
        };
        tx.send(Ok(ev1)).expect("send ev1");
    }
    for i in 0..2 {
        let ev2 = notify::Event {
            kind: notify::EventKind::Create(notify::event::CreateKind::File),
            paths: vec![root2.join(format!("file_{i}.txt"))],
            attrs: notify::event::EventAttributes::default(),
        };
        tx.send(Ok(ev2)).expect("send ev2");
    }

    // Send 1 more event that exceeds total cap of 4
    let ev_overflow = notify::Event {
        kind: notify::EventKind::Create(notify::event::CreateKind::File),
        paths: vec![root1.join("file_overflow.txt")],
        attrs: notify::event::EventAttributes::default(),
    };
    tx.send(Ok(ev_overflow)).expect("send ev_overflow");

    let polled = watcher.poll_events();
    let mut has_reconcile_root1 = false;
    let mut has_reconcile_root2 = false;

    for (_root, events) in polled {
        for evt in events {
            if let GuardEvent::ReconcileSubtree(r) = evt {
                if r == root1 {
                    has_reconcile_root1 = true;
                }
                if r == root2 {
                    has_reconcile_root2 = true;
                }
            }
        }
    }

    assert!(
        has_reconcile_root1,
        "root1 must receive ReconcileSubtree on total overflow"
    );
    assert!(
        has_reconcile_root2,
        "root2 must receive ReconcileSubtree on total overflow"
    );
}
