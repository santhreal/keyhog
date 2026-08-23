//! WHY THIS TEST EXISTS:
//! Row 69 / Unbounded cache growth and multi-kind eviction totality contract:
//! Proves that all cache kinds (Hyperscan shards, detector plans, GPU programs,
//! matcher artifacts, and lock files) are enumerated at run time, each obeys
//! registered count and byte eviction bounds, least-recently-written eviction order is strictly enforced,
//! and stale lock files older than bounded age are collected.
//!
//! WHAT IT DOES NOT CATCH:
//! Kernel disk corruption or OS-level file permission denial on unlinked inodes.

use keyhog_core::{CacheEvictionPolicy, CacheKind};
use keyhog_scanner::{
    collect_stale_lock_files, evict_cache_dir_with_policy, reconcile_all_cache_kinds,
};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

fn set_mtime(path: &Path, time: SystemTime) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open file for mtime update");
    let times = std::fs::FileTimes::new().set_modified(time);
    file.set_times(times).expect("set modified time");
}

#[test]
fn all_cache_kinds_are_enumerable_and_have_default_policies() {
    let kinds = CacheKind::ALL;
    assert_eq!(
        kinds.len(),
        5,
        "Exactly 5 cache kinds must be registered in the workspace"
    );

    let mut seen_labels = BTreeSet::new();
    for kind in kinds {
        let label = kind.label();
        assert!(!label.is_empty(), "Cache kind label must not be empty");
        assert!(
            seen_labels.insert(label),
            "Duplicate cache kind label: {label}"
        );

        let policy = kind.default_policy();
        assert!(
            policy.max_entries > 0,
            "Cache kind {label} max_entries must be greater than 0"
        );
        assert!(
            policy.max_bytes > 0,
            "Cache kind {label} max_bytes must be greater than 0"
        );
        assert!(
            policy.max_lock_age_secs > 0,
            "Cache kind {label} max_lock_age_secs must be greater than 0"
        );
    }
}

#[test]
fn cache_kind_path_classification_and_matching() {
    assert!(
        CacheKind::HyperscanShards.matches_path(Path::new("/tmp/keyhog/hs-0123456789abcdef.db"))
    );
    assert!(CacheKind::DetectorPlans
        .matches_path(Path::new("/tmp/keyhog/detectors-0123456789abcdef.json")));
    assert!(CacheKind::GpuPrograms.matches_path(Path::new("/tmp/keyhog/programs/literal_01.bin")));
    assert!(CacheKind::MatcherArtifacts.matches_path(Path::new("/tmp/keyhog/matcher-012345.khm")));
    assert!(CacheKind::LockFiles.matches_path(Path::new("/tmp/keyhog/operation.lock")));

    assert_eq!(
        CacheKind::classify_path(Path::new("/tmp/hs-deadbeef.db")),
        Some(CacheKind::HyperscanShards)
    );
    assert_eq!(
        CacheKind::classify_path(Path::new("/tmp/detectors-123456.json")),
        Some(CacheKind::DetectorPlans)
    );
    assert_eq!(
        CacheKind::classify_path(Path::new("/tmp/programs/match.bin")),
        Some(CacheKind::GpuPrograms)
    );
    assert_eq!(
        CacheKind::classify_path(Path::new("/tmp/artifact.khm")),
        Some(CacheKind::MatcherArtifacts)
    );
    assert_eq!(
        CacheKind::classify_path(Path::new("/tmp/sync.lock")),
        Some(CacheKind::LockFiles)
    );
}

#[test]
fn eviction_enforces_count_and_byte_bounds_with_lru_ordering() {
    let temp = TempDir::new().expect("tempdir");
    let cache_dir = temp.path();

    // Create 5 Hyperscan shards with staggered mtimes and 100 bytes each
    let mut files = Vec::new();
    for i in 0..5 {
        let file_path = cache_dir.join(format!("hs-{:016x}.db", i));
        std::fs::write(&file_path, vec![b'A' + i as u8; 100]).expect("write file");

        // Set staggered file mtime: file 0 is oldest, file 4 is newest
        let past = SystemTime::now() - Duration::from_secs(500 - i * 100);
        set_mtime(&file_path, past);
        files.push(file_path);
    }

    // Policy: max 2 entries, max 250 bytes
    let policy = CacheEvictionPolicy::new(2, 250, 600);
    let report = evict_cache_dir_with_policy(cache_dir, CacheKind::HyperscanShards, policy);

    assert_eq!(report.initial_count, 5);
    assert_eq!(report.initial_bytes, 500);
    assert_eq!(report.evicted_count, 3);
    assert_eq!(report.evicted_bytes, 300);
    assert_eq!(report.retained_count, 2);
    assert_eq!(report.retained_bytes, 200);

    // Oldest files (0, 1, 2) must be deleted
    assert!(!files[0].exists(), "Oldest file 0 must be evicted");
    assert!(!files[1].exists(), "Oldest file 1 must be evicted");
    assert!(!files[2].exists(), "Oldest file 2 must be evicted");

    // Newest files (3, 4) must be retained
    assert!(files[3].exists(), "Newer file 3 must be retained");
    assert!(files[4].exists(), "Newest file 4 must be retained");
}

#[test]
fn stale_lock_files_are_collected() {
    let temp = TempDir::new().expect("tempdir");
    let cache_dir = temp.path();

    let fresh_lock = cache_dir.join("fresh.lock");
    let stale_lock = cache_dir.join("stale.lock");

    std::fs::write(&fresh_lock, b"active").expect("write fresh lock");
    std::fs::write(&stale_lock, b"abandoned").expect("write stale lock");

    // Fresh lock is current
    set_mtime(&fresh_lock, SystemTime::now());

    // Stale lock is 2 hours old
    let past = SystemTime::now() - Duration::from_secs(7200);
    set_mtime(&stale_lock, past);

    let removed = collect_stale_lock_files(cache_dir, Duration::from_secs(600));
    assert_eq!(removed, 1, "Exactly 1 stale lock file must be removed");

    assert!(fresh_lock.exists(), "Fresh lock file must be preserved");
    assert!(!stale_lock.exists(), "Stale lock file must be deleted");
}

#[test]
fn actively_held_flock_lock_files_are_never_collected_even_when_old() {
    let temp = TempDir::new().expect("tempdir");
    let cache_dir = temp.path();

    let state_file = cache_dir.join("active_state.json");
    let held_lock_path = cache_dir.join("active_state.json.lock");

    let _lock = keyhog_core::StateFileWriteLock::acquire(&state_file)
        .expect("acquire state file write lock");

    // Set mtime to 2 hours in the past
    let past = SystemTime::now() - Duration::from_secs(7200);
    set_mtime(&held_lock_path, past);

    // Attempt collection with 600s threshold
    let removed = collect_stale_lock_files(cache_dir, Duration::from_secs(600));
    assert_eq!(
        removed, 0,
        "Actively held lock file must not be removed by stale lock collection"
    );
    assert!(
        held_lock_path.exists(),
        "Actively held lock file must remain on disk"
    );
}

#[test]
fn single_newest_entry_larger_than_byte_cap_is_retained() {
    let temp = TempDir::new().expect("tempdir");
    let cache_dir = temp.path();

    let file_path = cache_dir.join("hs-large.db");
    std::fs::write(&file_path, vec![b'X'; 500]).expect("write 500 byte file");

    // Policy: max 10 entries, max 100 bytes (file is 500 bytes)
    let policy = CacheEvictionPolicy::new(10, 100, 600);
    let report = evict_cache_dir_with_policy(cache_dir, CacheKind::HyperscanShards, policy);

    assert_eq!(report.initial_count, 1);
    assert_eq!(report.initial_bytes, 500);
    assert_eq!(
        report.retained_count, 1,
        "Single newest entry must be retained rather than thrashed"
    );
    assert!(file_path.exists());
}

#[test]
fn reconcile_all_cache_kinds_processes_mixed_cache_root() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    let prog_dir = root.join("programs");
    std::fs::create_dir(&prog_dir).expect("create programs dir");

    std::fs::write(root.join("hs-test1.db"), b"hs").expect("write hs");
    std::fs::write(root.join("detectors-test1.json"), b"json").expect("write detector");
    std::fs::write(prog_dir.join("matcher.bin"), b"gpu").expect("write gpu");
    std::fs::write(root.join("matcher-test.khm"), b"khm").expect("write khm");
    std::fs::write(root.join("stale.lock"), b"lock").expect("write lock");

    let past = SystemTime::now() - Duration::from_secs(7200);
    set_mtime(&root.join("stale.lock"), past);

    let results = reconcile_all_cache_kinds(root);
    assert_eq!(
        results.len(),
        5,
        "Reconcile must report on all 5 registered cache kinds"
    );

    let kinds_reported: BTreeSet<CacheKind> = results.iter().map(|(kind, _)| *kind).collect();
    for &expected in CacheKind::ALL {
        assert!(
            kinds_reported.contains(&expected),
            "CacheKind {expected} must be reported in reconcile results"
        );
    }
}

#[test]
fn eviction_ignores_symlinks_and_never_deletes_outside_files() {
    let temp_cache = TempDir::new().expect("tempdir cache");
    let temp_outside = TempDir::new().expect("tempdir outside");

    let outside_file = temp_outside.path().join("valuable.bin");
    std::fs::write(&outside_file, b"do not delete me").expect("write outside file");

    // Create a symlink inside cache_dir pointing to the outside directory or file
    #[cfg(unix)]
    {
        let symlink_dir = temp_cache.path().join("programs");
        let _ = std::os::unix::fs::symlink(temp_outside.path(), &symlink_dir);

        let policy = CacheEvictionPolicy::new(0, 0, 600);
        let report = evict_cache_dir_with_policy(temp_cache.path(), CacheKind::GpuPrograms, policy);

        assert_eq!(
            report.evicted_count, 0,
            "Symlinked directories must not be traversed or evicted"
        );
        assert!(
            outside_file.exists(),
            "Files outside cache root must never be unlinked via symlinks"
        );
    }
}

#[test]
fn eviction_ignores_deeply_nested_subdirectories() {
    let temp = TempDir::new().expect("tempdir");
    let cache_dir = temp.path();

    let deep_dir = cache_dir.join("programs").join("nested").join("deep");
    std::fs::create_dir_all(&deep_dir).expect("create deep dir");

    let deep_file = deep_dir.join("gpu-deep.bin");
    std::fs::write(&deep_file, b"deep artifact").expect("write deep file");

    let past = SystemTime::now() - Duration::from_secs(7200);
    set_mtime(&deep_file, past);

    let policy = CacheEvictionPolicy::new(0, 0, 600);
    let report = evict_cache_dir_with_policy(cache_dir, CacheKind::GpuPrograms, policy);

    assert_eq!(
        report.evicted_count, 0,
        "Files in subdirectories deeper than programs/ must not be collected"
    );
    assert!(
        deep_file.exists(),
        "Deeply nested file must remain untouched"
    );
}

#[test]
fn package_manager_locks_and_dotfiles_are_never_classified_or_collected() {
    assert_eq!(CacheKind::classify_path(Path::new("/tmp/Cargo.lock")), None);
    assert_eq!(CacheKind::classify_path(Path::new("/tmp/yarn.lock")), None);
    assert_eq!(CacheKind::classify_path(Path::new("/tmp/flake.lock")), None);
    assert_eq!(
        CacheKind::classify_path(Path::new("/tmp/.installed_manifest.json")),
        None
    );

    let temp = TempDir::new().expect("tempdir");
    let cache_dir = temp.path();
    let cargo_lock = cache_dir.join("Cargo.lock");
    std::fs::write(&cargo_lock, b"[lockfile]").expect("write cargo lock");
    let past = SystemTime::now() - Duration::from_secs(7200);
    set_mtime(&cargo_lock, past);

    let removed = collect_stale_lock_files(cache_dir, Duration::from_secs(600));
    assert_eq!(
        removed, 0,
        "Package manager lock files must never be removed"
    );
    assert!(cargo_lock.exists());
}

#[test]
fn installed_gpu_artifacts_and_manifests_are_never_evicted() {
    let temp = TempDir::new().expect("tempdir");
    let cache_dir = temp.path();
    let prog_dir = cache_dir.join("programs");
    std::fs::create_dir(&prog_dir).expect("create programs dir");

    let installed_file = prog_dir.join("installed_sidecar.bin");
    std::fs::write(&installed_file, b"installed binary").expect("write installed file");

    let manifest = serde_json::json!({
        "version": 1,
        "artifacts": [
            {
                "file_name": "installed_sidecar.bin",
                "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }
        ]
    });
    std::fs::write(
        prog_dir.join(".installed_manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .expect("write manifest");

    let ephemeral_file = prog_dir.join("gpu-ephemeral.bin");
    std::fs::write(&ephemeral_file, b"ephemeral").expect("write ephemeral file");

    let past = SystemTime::now() - Duration::from_secs(7200);
    set_mtime(&installed_file, past);
    set_mtime(&ephemeral_file, past);

    let policy = CacheEvictionPolicy::new(0, 0, 600);
    let report = evict_cache_dir_with_policy(cache_dir, CacheKind::GpuPrograms, policy);

    assert_eq!(
        report.evicted_count, 1,
        "Only ephemeral GPU program should be evicted"
    );
    assert!(!ephemeral_file.exists());
    assert!(
        installed_file.exists(),
        "Installed GPU sidecar must be protected from eviction"
    );
    assert!(prog_dir.join(".installed_manifest.json").exists());
}

#[test]
fn corrupt_manifest_skips_gpu_program_eviction_fail_closed() {
    let temp = TempDir::new().expect("tempdir");
    let cache_dir = temp.path();
    let prog_dir = cache_dir.join("programs");
    std::fs::create_dir(&prog_dir).expect("create programs dir");

    let sidecar_file = prog_dir.join("installed_sidecar.bin");
    std::fs::write(&sidecar_file, b"installed binary").expect("write sidecar");

    // Write corrupt/invalid manifest
    std::fs::write(
        prog_dir.join(".installed_manifest.json"),
        b"{ not valid json ...",
    )
    .expect("write corrupt manifest");

    let policy = CacheEvictionPolicy::new(0, 0, 600);
    let report = evict_cache_dir_with_policy(cache_dir, CacheKind::GpuPrograms, policy);

    assert_eq!(
        report.evicted_count, 0,
        "Corrupt manifest must cause fail-closed skip of GpuPrograms eviction"
    );
    assert!(
        sidecar_file.exists(),
        "Sidecar file must not be deleted when manifest is unreadable"
    );
}

#[test]
fn lock_files_eviction_report_parity() {
    let temp = TempDir::new().expect("tempdir");
    let cache_dir = temp.path();

    let fresh_lock = cache_dir.join("calibration.json.lock");
    let stale_lock = cache_dir.join("merkle_index.json.lock");

    std::fs::write(&fresh_lock, b"active").expect("write fresh lock");
    std::fs::write(&stale_lock, b"abandoned").expect("write stale lock");

    set_mtime(&fresh_lock, SystemTime::now());
    set_mtime(&stale_lock, SystemTime::now() - Duration::from_secs(7200));

    let policy = CacheKind::LockFiles.default_policy();
    let report = evict_cache_dir_with_policy(cache_dir, CacheKind::LockFiles, policy);

    assert_eq!(report.initial_count, 2);
    assert_eq!(report.stale_locks_removed, 1);
    assert_eq!(report.evicted_count, 1);
    assert_eq!(report.retained_count, 1);
    assert!(fresh_lock.exists());
    assert!(!stale_lock.exists());
}

#[test]
fn matcher_artifact_max_entries_constant_matches_policy() {
    assert_eq!(
        keyhog_scanner::MATCHER_ARTIFACT_MAX_ENTRIES,
        CacheKind::MatcherArtifacts.default_policy().max_entries,
        "MATCHER_ARTIFACT_MAX_ENTRIES must match policy default exactly"
    );
}
