//! Static-string interner for the frozen detector-metadata universe.
//!
//! Built once at scanner construction from the universe of metadata
//! strings that are stable across a scan run - every detector's
//! `id`, `name`, `service`, plus the small set of `source_type`
//! literals every source backend uses (`filesystem`, `git`,
//! `git/history`, `stdin`, `s3`, `docker`, `web`, `github`, `slack`).
//!
//! At scan time, `lookup(s)` returns a pre-allocated `Arc<str>` for
//! known strings without touching the global allocator. Unknown
//! strings (file paths, commit SHAs, author names, dates) fall
//! through to the per-scan `HashSet` interner in `ScanState`.
//!
//! ## Lookup backing: single-hash `ahash` map (PERF-locality_intern-1)
//!
//! The interner previously used vyre's CHD perfect hash. CHD is O(1) in the
//! big-O sense, but its constant factor is FOUR full-key traversals per lookup:
//! two seeded FNV-1a passes (bucket + slot), one xxHash-style verify pass, and a
//! final byte-for-byte `arc == s` compare. FNV-1a folds one byte per loop
//! iteration, so on the per-match hot path (three metadata fields per emitted
//! finding) that is twelve whole-key traversals per match - the dominant cost
//! the locality tripwire pins.
//!
//! `lookup` now resolves through a single `ahash` map keyed by the interned
//! string. `ahash` mixes the key in 8-byte words with hardware multiply/rotate
//! ops rather than one function call per byte, so a lookup is ONE fast hash +
//! one bucket compare instead of three byte-loops + a compare. The map stores
//! the arena index, and we return `arena[idx].clone()` - byte-identical to the
//! string the CHD path returned. The map is built once and read-only at scan
//! time, so every rayon worker shares it lock-free (an `&HashMap` read needs no
//! synchronization). For callers that already hold the detector index, the
//! scanner caches the resolved triple by index and skips `lookup` entirely
//! (`CompiledScanner::interned_detector_metadata`).

use std::sync::Arc;

/// Stable source-type identifiers every keyhog source backend
/// emits. Pre-interned because every match lands a copy of one of
/// these in `MatchLocation::source`. Keep this list in sync with
/// `keyhog_sources::Source::name()` implementations.
pub(crate) const SEED_SOURCE_TYPES: &[&str] = &[
    "filesystem",
    "git",
    "git/head",
    "git/history",
    "git/unreachable",
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
///
/// `index` maps each interned string to its slot in `arena`; it is read-only
/// after construction, so concurrent `lookup`s need no synchronization. The
/// `ahash` hasher gives a single fast (8-byte-word, hardware-mixed) hash per
/// lookup instead of the CHD perfect hash's three per-byte hash passes.
#[derive(Default)]
pub(crate) struct StaticInterner {
    arena: Vec<Arc<str>>,
    index: std::collections::HashMap<Arc<str>, u32, ahash::RandomState>,
}

impl StaticInterner {
    /// Build an interner from the universe of stable strings: detector
    /// metadata fields + the seed source-type list. Duplicates are
    /// collapsed automatically (the map keeps one entry per distinct key).
    pub(crate) fn from_detector_strings<I, S>(detector_strings: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        // Dedupe + freeze the input set. BTreeSet keeps the arena order stable
        // and deterministic across runs (matters for any index-keyed cache the
        // scanner derives from this arena, e.g. metadata_by_index).
        let mut all: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for s in detector_strings {
            all.insert(s.as_ref().to_owned());
        }
        for s in SEED_SOURCE_TYPES {
            all.insert((*s).to_owned());
        }

        if all.is_empty() {
            return Self::default();
        }

        let arena: Vec<Arc<str>> = all.iter().map(|s| Arc::from(s.as_str())).collect();
        let mut index: std::collections::HashMap<Arc<str>, u32, ahash::RandomState> =
            std::collections::HashMap::with_capacity_and_hasher(
                arena.len(),
                ahash::RandomState::new(),
            );
        for (i, arc) in arena.iter().enumerate() {
            index.insert(Arc::clone(arc), i as u32);
        }
        Self { arena, index }
    }

    /// Single-hash lookup. Returns a clone of the pre-allocated `Arc<str>`
    /// when `s` is in the interner; `None` otherwise. One `ahash` pass over the
    /// key plus a bucket compare - no second hash, no separate verify pass.
    /// `Arc<str>: Borrow<str>` makes `get(s)` allocation-free on hits.
    #[inline]
    pub(crate) fn lookup(&self, s: &str) -> Option<Arc<str>> {
        let &idx = self.index.get(s)?;
        // The index can only hold valid arena slots (populated from arena
        // above), but keep the bounds-checked `get` for a total function.
        self.arena.get(idx as usize).cloned()
    }

    /// Number of pre-interned strings.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.arena.len()
    }
}

#[cfg(test)]
pub(crate) fn seed_source_type_count() -> usize {
    SEED_SOURCE_TYPES.len()
}
