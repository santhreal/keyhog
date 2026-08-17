//! Centralized cache directory scanner, reconciler, and LRU eviction engine.
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

    // 1. Clean up stale lock files if requested
    if policy.max_lock_age_secs > 0 {
        report.stale_locks_removed =
            collect_stale_lock_files(cache_dir, Duration::from_secs(policy.max_lock_age_secs));
    }

    // 2. Discover all entries matching this CacheKind
    let mut entries = Vec::new();
    collect_matching_entries(cache_dir, kind, &mut entries);

    report.initial_count = entries.len();
    let mut current_bytes: u64 = entries.iter().map(|e| e.bytes).sum();
    report.initial_bytes = current_bytes;

    // 3. Sort oldest first (LRU order)
    entries.sort_by(|a, b| a.modified.cmp(&b.modified));

    // 4. Evict oldest until count <= max_entries and current_bytes <= max_bytes
    let mut remaining_count = entries.len();
    let mut retained_count = 0;

    for entry in entries {
        if remaining_count > policy.max_entries || current_bytes > policy.max_bytes {
            if std::fs::remove_file(&entry.path).is_ok() {
                report.evicted_count += 1;
                report.evicted_bytes += entry.bytes;
                current_bytes = current_bytes.saturating_sub(entry.bytes);
                remaining_count = remaining_count.saturating_sub(1);
                continue;
            }
        }
        retained_count += 1;
        remaining_count = remaining_count.saturating_sub(1);
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

/// Collect and remove all `.lock` files in `cache_dir` older than `max_age`.
pub fn collect_stale_lock_files(cache_dir: &Path, max_age: Duration) -> usize {
    let Ok(read_dir) = std::fs::read_dir(cache_dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut removed = 0;

    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Recurse into subdirectories (e.g. `programs/`)
            removed += collect_stale_lock_files(&path, max_age);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("lock") {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH); // LAW10: deterministic default epoch for sort ordering only; no effect on scan findings
            let age = now.duration_since(modified).unwrap_or(Duration::ZERO); // LAW10: conservative zero duration prevents premature lock collection; no effect on scan findings
            if age >= max_age {
                if std::fs::remove_file(&path).is_ok() {
                    removed += 1;
                }
            }
        }
    }
    removed
}

fn collect_matching_entries(dir: &Path, kind: CacheKind, out: &mut Vec<CacheEntry>) {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // For GPU programs or subdirectories, inspect inner contents
            if kind == CacheKind::GpuPrograms
                || path.file_name().and_then(|n| n.to_str()) == Some("programs")
            {
                collect_matching_entries(&path, kind, out);
            }
            continue;
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
