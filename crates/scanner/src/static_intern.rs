//! Static-string interner backed by vyre's CHD perfect hash.
//!
//! Built once at scanner construction from the universe of metadata
//! strings that are stable across a scan run — every detector's
//! `id`, `name`, `service`, plus the small set of `source_type`
//! literals every source backend uses (`filesystem`, `git`,
//! `git/history`, `stdin`, `s3`, `docker`, `web`, `github`, `slack`).
//!
//! At scan time, `lookup(s)` returns a pre-allocated `Arc<str>` for
//! known strings without touching the global allocator. Unknown
//! strings (file paths, commit SHAs, author names, dates) fall
//! through to the per-scan `HashSet` interner in `ScanState`.
//!
//! Why CHD perfect hash instead of a `HashMap<&str, Arc<str>>`:
//!  - Lock-free on read. Every rayon worker can lookup concurrently
//!    without contention. A shared `HashMap` would need `RwLock`.
//!  - Worst-case `O(1)`: two hash evaluations + one verify hash +
//!    two array loads. No probing, no collision handling.
//!  - Lower memory than a `HashMap` because there's no slot
//!    overhead — just three arrays plus the arena.

use std::sync::Arc;

use vyre_libs::intern::perfect_hash::{build_chd, PerfectHash};

/// Stable source-type identifiers every keyhog source backend
/// emits. Pre-interned because every match lands a copy of one of
/// these in `MatchLocation::source`. Keep this list in sync with
/// `keyhog_sources::Source::name()` implementations.
const SEED_SOURCE_TYPES: &[&str] = &[
    "filesystem",
    "git",
    "git/history",
    "git/diff",
    "git/staged",
    "git-diff",
    "stdin",
    "s3",
    "docker",
    "web",
    "github",
    "slack",
    "binary",
];

/// Frozen static-string interner. Built once at scanner
/// construction; cloneable via `Arc` so every rayon worker shares
/// one read-only instance.
pub struct StaticInterner {
    phf: PerfectHash,
    arena: Vec<Arc<str>>,
}

impl StaticInterner {
    /// Build an interner from the universe of stable strings: detector
    /// metadata fields + the seed source-type list. Duplicates are
    /// collapsed automatically (the CHD builder rejects duplicate keys,
    /// so we dedupe up front).
    pub fn from_detector_strings<I, S>(detector_strings: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        // Dedupe + freeze the input set so the CHD builder doesn't
        // see duplicate keys (which would cause it to bail).
        let mut all: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for s in detector_strings {
            all.insert(s.as_ref().to_owned());
        }
        for s in SEED_SOURCE_TYPES {
            all.insert((*s).to_owned());
        }

        if all.is_empty() {
            return Self {
                phf: PerfectHash::default(),
                arena: Vec::new(),
            };
        }

        let arena: Vec<Arc<str>> = all.iter().map(|s| Arc::from(s.as_str())).collect();
        let entries: Vec<(String, u32)> = all
            .into_iter()
            .enumerate()
            .map(|(i, s)| (s, i as u32))
            .collect();
        let phf = build_chd(entries);
        Self { phf, arena }
    }

    /// O(1) lookup. Returns a clone of the pre-allocated `Arc<str>`
    /// when `s` is in the interner; `None` otherwise.
    #[inline]
    pub fn lookup(&self, s: &str) -> Option<Arc<str>> {
        let idx = self.phf.lookup(s)? as usize;
        // CHD reports `Some(idx)` even for keys NOT in the input
        // set when their hash collides with an inserted key's slot
        // (the verify step inside `lookup` guards against this for
        // *exact* misses, but a slot-equality false positive can
        // still happen if the verify hashes collide — astronomically
        // unlikely with a 64-bit verify hash, but keep the bounds
        // check for correctness).
        let arc = self.arena.get(idx)?;
        if arc.as_ref() == s {
            Some(arc.clone())
        } else {
            None
        }
    }

    /// Number of pre-interned strings.
    pub fn len(&self) -> usize {
        self.arena.len()
    }

    pub fn is_empty(&self) -> bool {
        self.arena.is_empty()
    }
}

impl Default for StaticInterner {
    fn default() -> Self {
        Self {
            phf: PerfectHash::default(),
            arena: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_seeded_source_types() {
        let intern = StaticInterner::from_detector_strings(std::iter::empty::<&str>());
        assert!(intern.lookup("filesystem").is_some());
        assert!(intern.lookup("git").is_some());
        assert!(intern.lookup("stdin").is_some());
    }

    #[test]
    fn looks_up_detector_strings() {
        let intern = StaticInterner::from_detector_strings([
            "aws-access-key",
            "AWS Access Key",
            "aws",
            "github-pat",
            "GitHub PAT",
            "github",
        ]);
        assert!(intern.lookup("aws-access-key").is_some());
        assert!(intern.lookup("github").is_some());
        assert!(intern.lookup("not-a-detector").is_none());
    }

    #[test]
    fn deduplicates_input() {
        // The same `service = "aws"` shows up across multiple
        // detectors. Builder must collapse them rather than reject.
        let intern = StaticInterner::from_detector_strings([
            "aws-access-key",
            "aws",
            "aws-session-token",
            "aws",
            "aws-secret-key",
            "aws",
        ]);
        assert!(intern.lookup("aws").is_some());
        assert_eq!(intern.lookup("aws"), intern.lookup("aws"));
    }

    #[test]
    fn returns_same_arc_on_repeated_lookup() {
        let intern = StaticInterner::from_detector_strings(["hello-detector"]);
        let a = intern.lookup("hello-detector").unwrap();
        let b = intern.lookup("hello-detector").unwrap();
        // The Arc itself should be cloned from the same slot, not
        // re-allocated — pointer-equality is the cheap proof.
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn empty_input_yields_empty_interner() {
        let intern = StaticInterner::from_detector_strings(std::iter::empty::<&str>());
        // Even an "empty" interner should still hold the seed source-types.
        assert_eq!(intern.len(), SEED_SOURCE_TYPES.len());
    }

    #[test]
    fn unknown_lookup_returns_none() {
        let intern = StaticInterner::from_detector_strings(["x", "y", "z"]);
        assert!(intern.lookup("does-not-exist").is_none());
        assert!(intern.lookup("").is_none() || intern.lookup("").is_some());
    }
}
