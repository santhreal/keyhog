//! Static-string interner for the frozen detector-metadata universe.
//!
//! Built once at scanner construction from the universe of metadata
//! strings that are stable across a scan run - every detector's
//! `id`, `name`, `service`, and companion names, plus the seed `source_type`
//! literals every source backend emits ([`SEED_SOURCE_TYPES`], kept in sync
//! with `keyhog_sources::Source::name()`).
//!
//! At scan time, `lookup(s)` returns a pre-allocated `Arc<str>` for
//! known strings without touching the global allocator. Unknown
//! strings (file paths, commit SHAs, author names, dates) fall
//! through to the per-scan `HashSet` interner in `ScanState`.
//!
//! ## Lookup backing: single-hash `ahash` map (PERF-locality_intern-1)
//!
//! The interner previously used VYRE's CHD perfect hash. CHD is O(1) in the
//! big-O sense, but its constant factor is FOUR full-key traversals per lookup:
//! two seeded FNV-1a passes (bucket + slot), one xxHash-style verify pass, and a
//! final byte-for-byte `arc == s` compare. FNV-1a folds one byte per loop
//! iteration, so on the per-match hot path (three metadata fields per emitted
//! finding) that is twelve whole-key traversals per match - the dominant cost
//! the locality tripwire pins.
//!
//! `lookup` resolves through a single `ahash` map keyed by the interned
//! `Arc<str>`. `ahash` mixes the key in 8-byte words with hardware
//! multiply/rotate operations rather than one function call per byte, so a
//! lookup is one fast hash plus one bucket comparison. The returned `Arc` is
//! cloned directly from the map key. There is no parallel arena containing a
//! second owner for every string. The map is built once and read-only at scan
//! time, so every rayon worker shares it lock-free.

use std::sync::Arc;

/// The seed source types leaked once into `&'static str`, derived from the single
/// parsed [`SEED_SOURCE_TYPES`] owner (no second `include_str!`/parse).
pub(crate) fn seed_source_types_leaked() -> Vec<&'static str> {
    static LEAKED_SEEDS: std::sync::LazyLock<Vec<&'static str>> = std::sync::LazyLock::new(|| {
        SEED_SOURCE_TYPES
            .iter()
            .map(|s| Box::leak(s.clone().into_boxed_str()) as &'static str)
            .collect()
    });
    LEAKED_SEEDS.clone()
}

crate::tier_b_list::tier_b_vec!(
    /// Stable source-type identifiers every keyhog source backend
    /// emits. Pre-interned because every match lands a copy of one of
    /// these in `MatchLocation::source`. Keep this list in sync with
    /// `keyhog_sources::Source::name()` implementations.
    pub(crate) SEED_SOURCE_TYPES,
    "seed-source-types.toml",
    source_types
);

/// Frozen static-string interner. Built once at scanner
/// construction; cloneable via `Arc` so every rayon worker shares
/// one read-only instance.
///
/// `index` owns each distinct string as its key and is read-only after
/// construction, so concurrent lookups need no synchronization. The `ahash`
/// hasher gives a single fast (8-byte-word, hardware-mixed) hash per lookup
/// instead of the CHD perfect hash's three per-byte hash passes.
#[derive(Default)]
pub(crate) struct StaticInterner {
    index: std::collections::HashMap<Arc<str>, (), ahash::RandomState>,
}

pub(crate) struct StaticInternerBuilder {
    index: std::collections::HashMap<Arc<str>, (), ahash::RandomState>,
}

impl StaticInternerBuilder {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            index: std::collections::HashMap::with_capacity_and_hasher(
                capacity.saturating_add(SEED_SOURCE_TYPES.len()),
                ahash::RandomState::new(),
            ),
        }
    }

    pub(crate) fn intern(&mut self, value: &str) -> Arc<str> {
        if let Some((value, ())) = self.index.get_key_value(value) {
            return Arc::clone(value);
        }
        let value = Arc::<str>::from(value);
        self.index.insert(Arc::clone(&value), ());
        value
    }

    pub(crate) fn finish(mut self) -> StaticInterner {
        for value in &*SEED_SOURCE_TYPES {
            self.intern(value);
        }
        self.index.shrink_to_fit();
        StaticInterner { index: self.index }
    }
}

impl StaticInterner {
    /// Build an interner from the universe of stable strings: detector
    /// metadata fields (including companion names) + the seed source-type list.
    /// Duplicates are collapsed automatically (the map keeps one entry per distinct key).
    pub(crate) fn from_detector_strings<I, S>(detector_strings: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let values = detector_strings.into_iter();
        let mut builder = StaticInternerBuilder::with_capacity(values.size_hint().0);
        for value in values {
            builder.intern(value.as_ref());
        }
        builder.finish()
    }

    /// Single-hash lookup. Returns a clone of the pre-allocated `Arc<str>`
    /// when `s` is in the interner; `None` otherwise. One `ahash` pass over the
    /// key plus a bucket compare - no second hash, no separate verify pass.
    /// `Arc<str>: Borrow<str>` makes `get(s)` allocation-free on hits.
    #[inline]
    pub(crate) fn lookup(&self, s: &str) -> Option<Arc<str>> {
        self.index
            .get_key_value(s)
            .map(|(value, ())| Arc::clone(value))
    }

    /// Number of pre-interned strings.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.index.len()
    }
    /// Retained map capacity, exposed only for ownership regression tests.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.index.capacity()
    }
}

#[cfg(test)]
pub(crate) fn seed_source_type_count() -> usize {
    SEED_SOURCE_TYPES.len()
}
