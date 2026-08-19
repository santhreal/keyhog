//! WHY: Closes the defect class where network and userspace filesystems (NFS, SMB/CIFS,
//! 9P, FUSE, AFS, CEPH, overlay) that do not generate authoritative kernel-level file
//! change events were silently treated as fully watched, leading to undetected secret
//! modifications when changes occurred remotely or bypassed local inotify (Row 132).
//!
//! What this does NOT catch: physical block-device corruptions or hardware controller failures.

use keyhog::daemon::fs_probe::{
    classify_filesystem_type, probe_filesystem_authority,
    DEFAULT_UNAUTHORITATIVE_SCRUB_INTERVAL_SECS, TEST_FORCE_FS_AUTHORITY_ENV,
};
use keyhog::daemon::guard_runtime::GuardRuntime;
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
fn row_132_test_force_fs_authority_env_override() {
    let dir = tempdir().expect("tempdir");

    // 1. Force authoritative
    std::env::set_var(TEST_FORCE_FS_AUTHORITY_ENV, "nfs:authoritative");
    let auth = probe_filesystem_authority(dir.path());
    assert_eq!(auth.filesystem_type, "nfs");
    assert!(auth.authoritative);
    assert!(auth.unauthoritative_reason.is_none());

    // 2. Force unauthoritative with custom reason
    std::env::set_var(
        TEST_FORCE_FS_AUTHORITY_ENV,
        "ext4:unauthoritative:test-simulated-network-mount",
    );
    let auth = probe_filesystem_authority(dir.path());
    assert_eq!(auth.filesystem_type, "ext4");
    assert!(!auth.authoritative);
    assert_eq!(
        auth.unauthoritative_reason.as_deref(),
        Some("test-simulated-network-mount")
    );

    // Clean up env
    std::env::remove_var(TEST_FORCE_FS_AUTHORITY_ENV);
}

#[test]
fn row_132_local_path_probe_returns_authoritative_on_standard_mounts() {
    std::env::remove_var(TEST_FORCE_FS_AUTHORITY_ENV);
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

    // When scrub triggers, the root transitions Stopped then ReconciliationStarted into Indexing
    rt.transition_root(&root_path, &GuardTransition::Stopped)
        .expect("scrub stop");
    rt.transition_root(&root_path, &GuardTransition::ReconciliationStarted)
        .expect("scrub reconcile start");
    assert_eq!(rt.root_state(&root_path), Some(GuardRootState::Indexing));
    // And finishes clean
    rt.transition_root(&root_path, &GuardTransition::ReconciliationClean)
        .expect("scrub reconcile clean");
    assert_eq!(rt.root_state(&root_path), Some(GuardRootState::Current));
}
