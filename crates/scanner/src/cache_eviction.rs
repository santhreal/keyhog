//! Centralized cache directory scanner, reconciler, and least-recently-written eviction engine.
//!
//! Enforces bounded growth across all KeyHog cache artifact kinds:
//! - Hyperscan pattern databases (`hs-*.db`)
//! - Detector parse plans (`detectors-*.json`)
//! - Compiled GPU matchers (`programs/*`)
//! - MatcherArtifact graphs (`*.khm`)
//! - Stale inter-process synchronization locks (`*.lock`)

use keyhog_core::{CacheEvictionPolicy, CacheKind};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Detailed report of cache reconciliation and eviction actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EvictionReport {
    /// Number of entries observed before eviction.
    pub initial_count: usize,
    /// Total bytes observed before eviction.
    pub initial_bytes: u64,
    /// Number of entries successfully evicted.
    pub evicted_count: usize,
    /// Total bytes freed by eviction.
    pub evicted_bytes: u64,
    /// Number of entries remaining after eviction.
    pub retained_count: usize,
    /// Total bytes remaining after eviction.
    pub retained_bytes: u64,
    /// Number of stale lock files removed.
    pub stale_locks_removed: usize,
}

#[derive(Debug)]
struct CacheEntry {
    path: PathBuf,
    modified: SystemTime,
    bytes: u64,
}

/// Evict artifacts of a specific `CacheKind` in `cache_dir` according to `policy`.
pub fn evict_cache_dir_with_policy(
    cache_dir: &Path,
    kind: CacheKind,
    policy: CacheEvictionPolicy,
) -> EvictionReport {
    if !cache_dir.exists() || !cache_dir.is_dir() {
        return EvictionReport::default();
    }

    let mut report = EvictionReport::default();

    if kind == CacheKind::LockFiles {
        let mut entries = Vec::new();
        collect_matching_entries(cache_dir, kind, &mut entries);
        report.initial_count = entries.len();
        report.initial_bytes = entries.iter().map(|e| e.bytes).sum();

        if policy.max_lock_age_secs > 0 {
            report.stale_locks_removed =
                collect_stale_lock_files(cache_dir, Duration::from_secs(policy.max_lock_age_secs));
        }

        report.evicted_count = report.stale_locks_removed;
        let mut remaining_entries = Vec::new();
        collect_matching_entries(cache_dir, kind, &mut remaining_entries);
        report.retained_count = remaining_entries.len();
        report.retained_bytes = remaining_entries.iter().map(|e| e.bytes).sum();
        report.evicted_bytes = report.initial_bytes.saturating_sub(report.retained_bytes);
        return report;
    }

    // Discover all entries matching this CacheKind
    let mut entries = Vec::new();
    collect_matching_entries(cache_dir, kind, &mut entries);

    report.initial_count = entries.len();
    let mut current_bytes: u64 = entries.iter().map(|e| e.bytes).sum();
    report.initial_bytes = current_bytes;

    // Sort oldest first (least recently written by modification time)
    entries.sort_by(|a, b| a.modified.cmp(&b.modified));

    let total = entries.len();
    let mut retained_count = 0;

    for (idx, entry) in entries.into_iter().enumerate() {
        let is_newest = idx + 1 == total;
        let remaining_candidates = total - idx;
        let files_if_retained = retained_count + remaining_candidates;

        let over_count = files_if_retained > policy.max_entries;
        let over_bytes = current_bytes > policy.max_bytes;

        // If policy permits at least one entry, never evict the sole newest entry on byte cap
        let should_evict = if is_newest && retained_count == 0 && policy.max_entries >= 1 {
            false
        } else {
            over_count || over_bytes
        };

        if should_evict {
            match std::fs::remove_file(&entry.path) {
                Ok(()) => {
                    report.evicted_count += 1;
                    report.evicted_bytes += entry.bytes;
                    current_bytes = current_bytes.saturating_sub(entry.bytes);
                    continue;
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    current_bytes = current_bytes.saturating_sub(entry.bytes);
                    continue;
                }
                // LAW10: file cannot be removed due to permissions or io; it is retained in cache accounting
                Err(_) => {}
            }
        }
        retained_count += 1;
    }

    report.retained_count = retained_count;
    report.retained_bytes = current_bytes;
    report
}

/// Reconcile and evict all registered cache kinds under `cache_root` using default policies.
pub fn reconcile_all_cache_kinds(cache_root: &Path) -> Vec<(CacheKind, EvictionReport)> {
    let mut results = Vec::with_capacity(CacheKind::ALL.len());
    for &kind in CacheKind::ALL {
        let policy = kind.default_policy();
        let report = evict_cache_dir_with_policy(cache_root, kind, policy);
        results.push((kind, report));
    }
    results
}

/// Collect and remove stale `.lock` files in `cache_dir` older than `max_age`.
///
/// Only unlinks a `.lock` file if its age exceeds `max_age` AND an exclusive non-blocking
/// advisory lock (`try_lock_exclusive`) can be acquired, preventing the removal of actively-held locks.
pub fn collect_stale_lock_files(cache_dir: &Path, max_age: Duration) -> usize {
    collect_stale_locks_bounded(cache_dir, max_age, true)
}

fn collect_stale_locks_bounded(cache_dir: &Path, max_age: Duration, top_level: bool) -> usize {
    let Ok(read_dir) = std::fs::read_dir(cache_dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut removed = 0;

    for entry in read_dir.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        // Refuse symlinks: never follow symlinks
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            // Only inspect immediate `programs/` subfolder when at top level
            if top_level && path.file_name().and_then(|n| n.to_str()) == Some("programs") {
                removed += collect_stale_locks_bounded(&path, max_age, false);
            }
            continue;
        }
        if CacheKind::classify_path(&path) == Some(CacheKind::LockFiles) {
            if let Some(path_str) = path.to_str() {
                if let Some(target_str) = path_str.strip_suffix(".lock") {
                    if Path::new(target_str).exists() {
                        // Companion state/cache artifact still exists; keep its coordination lock file
                        continue;
                    }
                }
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH); // LAW10: deterministic default epoch for sort ordering only; no effect on scan findings
            let age = now.duration_since(modified).unwrap_or(Duration::ZERO); // LAW10: conservative zero duration prevents premature lock collection; no effect on scan findings
            if age >= max_age {
                // LAW10: unopenable lock file is conservatively skipped; no effect on scan findings
                if let Ok(file) = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                {
                    use fs2::FileExt;
                    if file.try_lock_exclusive().is_ok() {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            if let (Ok(m1), Ok(m2)) = (file.metadata(), std::fs::metadata(&path)) {
                                if m1.ino() == m2.ino() && m1.dev() == m2.dev() && m1.nlink() > 0 {
                                    if std::fs::remove_file(&path).is_ok() {
                                        removed += 1;
                                    }
                                }
                            }
                        }
                        #[cfg(not(unix))]
                        {
                            if std::fs::remove_file(&path).is_ok() {
                                removed += 1;
                            }
                        }
                        let _ = file.unlock(); // LAW10: no runtime effect; unlocking unlinked descriptor cleans up kernel lock table entry
                    }
                }
            }
        }
    }
    removed
}

fn collect_matching_entries(cache_root: &Path, kind: CacheKind, out: &mut Vec<CacheEntry>) {
    collect_matching_entries_bounded(cache_root, kind, out, true);
}

/// Count cached files matching the specified kind without eviction.
pub fn count_matching_entries(cache_root: &Path, kind: CacheKind) -> usize {
    let mut out = Vec::new();
    collect_matching_entries(cache_root, kind, &mut out);
    out.len()
}

fn collect_matching_entries_bounded(
    dir: &Path,
    kind: CacheKind,
    out: &mut Vec<CacheEntry>,
    top_level: bool,
) {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return;
    };

    let mut protected_files = std::collections::HashSet::new();
    if kind == CacheKind::GpuPrograms {
        let manifest_path = dir.join(".installed_manifest.json");
        if manifest_path.exists() {
            if let Ok(bytes) = std::fs::read(&manifest_path) {
                #[derive(serde::Deserialize)]
                struct Manifest {
                    #[serde(default)]
                    artifacts: Vec<Entry>,
                }
                #[derive(serde::Deserialize)]
                struct Entry {
                    file_name: String,
                }
                if let Ok(manifest) = serde_json::from_slice::<Manifest>(&bytes) {
                    for item in manifest.artifacts {
                        protected_files.insert(item.file_name);
                    }
                } else {
                    // Malformed manifest exists: fail closed and do not collect/evict any GpuPrograms
                    return;
                }
            } else {
                // Unreadable manifest exists: fail closed and do not collect/evict any GpuPrograms
                return;
            }
        }
    }

    for entry in read_dir.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        // Refuse symlinks: never follow symlinks outside cache root
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            // Only inspect immediate `programs/` subfolder when at top level
            if top_level && path.file_name().and_then(|n| n.to_str()) == Some("programs") {
                collect_matching_entries_bounded(&path, kind, out, false);
            }
            continue;
        }

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('.') || protected_files.contains(name) {
                continue;
            }
        }

        if kind.matches_path(&path) {
            if let Ok(meta) = entry.metadata() {
                // LAW10: unreadable metadata skips entry without aborting eviction of other artifacts
                let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH); // LAW10: deterministic default epoch for LRU sort ordering only; no effect on scan findings
                let bytes = meta.len();
                out.push(CacheEntry {
                    path,
                    modified,
                    bytes,
                });
            }
        }
    }
}
