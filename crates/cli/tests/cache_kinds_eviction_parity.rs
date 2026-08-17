//! WHY THIS TEST EXISTS:
//! Row 69 / Unbounded cache growth and multi-kind eviction totality contract:
//! Proves that all cache kinds (Hyperscan shards, detector plans, GPU programs,
//! matcher artifacts, and lock files) are enumerated at run time, each obeys
//! registered count and byte eviction bounds, LRU eviction order is strictly enforced,
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
