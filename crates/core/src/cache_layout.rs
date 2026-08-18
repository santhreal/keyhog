//! Unified cache layout classification and eviction policy contracts.
//!
//! KeyHog produces persistent artifacts across several sub-systems: Hyperscan
//! pattern shard databases (`hs-*.db`), pre-parsed detector JSON plans
//! (`detectors-*.json`), compiled GPU literal set programs (`programs/*`),
//! and persistent matcher artifact graphs (`*.khm`). Inter-process lock files
//! (`*.lock`) coordinate atomic writes and cache updates.
//!
//! This module provides the single canonical owner of cache artifact classification
//! and registered eviction policies (count limits, byte caps, and lock age bounds).

use serde::{Deserialize, Serialize};
use std::path::Path;

/// All distinct cache artifact kinds managed by KeyHog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheKind {
    /// Hyperscan / Vectorscan compiled regex pattern shard databases (`hs-<key>.db`).
    HyperscanShards,
    /// Pre-parsed detector corpus JSON plans (`detectors-<key>.json`).
    DetectorPlans,
    /// Compiled GPU literal-set binary matchers (`programs/*`).
    GpuPrograms,
    /// Eager compiled matcher artifact graphs (`*.khm`).
    MatcherArtifacts,
    /// Inter-process write and synchronization lock files (`*.lock`).
    LockFiles,
}

impl CacheKind {
    /// The complete list of registered cache kinds.
    pub const ALL: &'static [CacheKind] = &[
        CacheKind::HyperscanShards,
        CacheKind::DetectorPlans,
        CacheKind::GpuPrograms,
        CacheKind::MatcherArtifacts,
        CacheKind::LockFiles,
    ];

    /// Operator-facing label for the cache kind.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::HyperscanShards => "hyperscan-shards",
            Self::DetectorPlans => "detector-plans",
            Self::GpuPrograms => "gpu-programs",
            Self::MatcherArtifacts => "matcher-artifacts",
            Self::LockFiles => "lock-files",
        }
    }

    /// Check whether a given filename or path matches this cache kind.
    #[must_use]
    pub fn matches_path(self, path: &Path) -> bool {
        Self::classify_path(path) == Some(self)
    }

    /// Classify a path into its respective `CacheKind` if recognized.
    #[must_use]
    pub fn classify_path(path: &Path) -> Option<Self> {
        let file_name = path.file_name()?.to_str()?;
        if file_name.starts_with('.') {
            return None;
        }
        if file_name.ends_with(".lock") {
            let is_package_lock = matches!(
                file_name,
                "Cargo.lock"
                    | "flake.lock"
                    | "yarn.lock"
                    | "pnpm-lock.yaml"
                    | "composer.lock"
                    | "Gemfile.lock"
                    | "poetry.lock"
                    | "Pipfile.lock"
            );
            if !is_package_lock {
                return Some(Self::LockFiles);
            }
            return None;
        }
        if file_name.starts_with(crate::hyperscan_cache::HYPERSCAN_CACHE_PREFIX)
            && file_name.ends_with(crate::hyperscan_cache::HYPERSCAN_CACHE_SUFFIX)
        {
            return Some(Self::HyperscanShards);
        }
        if file_name.starts_with("detectors-") && file_name.ends_with(".json") {
            return Some(Self::DetectorPlans);
        }
        if file_name.ends_with(crate::MATCHER_ARTIFACT_SUFFIX) {
            return Some(Self::MatcherArtifacts);
        }
        let in_programs_dir = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == "programs");
        let is_gpu_matcher_file = file_name.starts_with("gpu-") && file_name.ends_with(".bin");
        let is_program_binary = in_programs_dir
            && (file_name.ends_with(".bin")
                || (file_name.len() == 64 && file_name.chars().all(|c| c.is_ascii_hexdigit()))
                || file_name.starts_with("gpu-"));
        if is_gpu_matcher_file || is_program_binary {
            return Some(Self::GpuPrograms);
        }
        None
    }

    /// Return the canonical default eviction policy for this cache kind.
    #[must_use]
    pub const fn default_policy(self) -> CacheEvictionPolicy {
        match self {
            Self::HyperscanShards => CacheEvictionPolicy {
                max_entries: 128,
                max_bytes: 512 * 1024 * 1024, // 512 MiB
                max_lock_age_secs: 600,
            },
            Self::DetectorPlans => CacheEvictionPolicy {
                max_entries: 16,
                max_bytes: 64 * 1024 * 1024, // 64 MiB
                max_lock_age_secs: 600,
            },
            Self::GpuPrograms => CacheEvictionPolicy {
                max_entries: 64,
                max_bytes: 128 * 1024 * 1024, // 128 MiB
                max_lock_age_secs: 600,
            },
            Self::MatcherArtifacts => CacheEvictionPolicy {
                max_entries: 8,
                max_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB (allows 8 entries at the 256 MiB per-file limit)
                max_lock_age_secs: 600,
            },
            Self::LockFiles => CacheEvictionPolicy {
                max_entries: 1024,
                max_bytes: 10 * 1024 * 1024, // 10 MiB
                max_lock_age_secs: 600,      // 10 minutes
            },
        }
    }
}

impl std::fmt::Display for CacheKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Eviction policy governing count limits, byte caps, and stale lock reclamation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEvictionPolicy {
    /// Maximum number of artifact entries retained.
    pub max_entries: usize,
    /// Maximum total bytes occupied by artifacts of this kind.
    pub max_bytes: u64,
    /// Maximum allowed age for lock files before they are collected as stale.
    pub max_lock_age_secs: u64,
}

impl CacheEvictionPolicy {
    /// Create a custom policy with explicit entries and byte bounds.
    #[must_use]
    pub const fn new(max_entries: usize, max_bytes: u64, max_lock_age_secs: u64) -> Self {
        Self {
            max_entries,
            max_bytes,
            max_lock_age_secs,
        }
    }
}
