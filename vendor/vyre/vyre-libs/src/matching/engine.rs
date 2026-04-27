//! Common abstractions over the matching engines in `vyre-libs`.
//!
//! Every concrete engine in this crate (`GpuLiteralSet`, `DirectGpuScanner`,
//! `RulePipeline`, future ones for parsers / taint flow / anomaly scoring)
//! ships the same shape of public API:
//!
//!   1. A `compile(...)` constructor that takes some pattern set.
//!   2. A `scan(&backend, &haystack, max_matches)` GPU dispatch.
//!   3. A `scan_cpu(&haystack)` parity reference.
//!   4. A `to_bytes()` / `from_bytes(...)` cache pair.
//!
//! Until now each engine duplicated the trait shape ad-hoc. This module
//! is the lego-block fix: one set of traits, one generic
//! `cached_load_or_compile` helper, every engine plugs in.
//!
//! # Why two traits, not one
//!
//! - [`MatchScan`] is dyn-safe (no associated types, no `Sized`). Consumers
//!   can store `Box<dyn MatchScan>` to swap engines at runtime — keyhog's
//!   backend selection (`KEYHOG_BACKEND=mega-scan`) becomes a runtime
//!   trait-object swap instead of a hardcoded match arm.
//! - [`MatchEngineCache`] keeps typed errors (each engine's own
//!   `WireError` enum with its specific variants), so the cache layer's
//!   error messages stay actionable. Object-safety isn't needed here:
//!   cache wiring always knows the concrete type at compile time.
//!
//! Engines implement BOTH; consumers pick whichever fits their call site.
//!
//! # Cache wiring rule (Torvalds-style: do it once)
//!
//! [`cached_load_or_compile`] is the only blessed way to wire a cache.
//! Consumers (keyhog, surgec) should never re-implement the load/compile
//! /save dance. If a new engine needs special cache invalidation logic
//! (e.g. dropping the cache on certain ABI bumps), extend this helper —
//! don't fork it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use vyre::VyreBackend;
use vyre_foundation::match_result::Match;

/// Diagnostic-bearing wrapper around a scan result.
///
/// Every consumer pipeline ends up reconstructing these flags ad-hoc
/// (was the scan truncated? how long did it take? did we hit the
/// disk cache?). Centralising them gives downstream tooling
/// (telemetry pipelines, watch-mode dashboards, perf benches) a
/// single struct to read instead of parsing engine-specific output.
///
/// `ScanResult::matches` is the primary payload — consumers that
/// don't care about diagnostics can `result.matches` and ignore the
/// rest. The struct is `Clone` so it can be passed across thread
/// boundaries and `Default` so tests can fabricate empties.
#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    /// Sorted matches produced by the engine.
    pub matches: Vec<Match>,
    /// True when the engine hit the per-dispatch `max_matches` cap
    /// AND the underlying scan reported overflow. Consumers should
    /// treat truncated results as incomplete and re-scan with a
    /// larger cap if every match matters (security audits).
    pub truncated: bool,
    /// Total wall-clock time the scan call spent, including dispatch
    /// + readback. `Duration::ZERO` when the engine doesn't measure.
    pub elapsed: Duration,
    /// True when the engine was loaded from disk cache instead of
    /// being recompiled. Used by perf tooling to attribute cold-
    /// start cost.
    pub cache_hit: bool,
}

impl ScanResult {
    /// Build a result from a bare match vector. Diagnostic flags
    /// default to safe values (not truncated, zero elapsed, no
    /// cache hit). For engines that produce richer diagnostics,
    /// construct the struct directly.
    #[must_use]
    pub fn from_matches(matches: Vec<Match>) -> Self {
        Self {
            matches,
            ..Self::default()
        }
    }

    /// Number of matches produced.
    #[must_use]
    pub fn len(&self) -> usize {
        self.matches.len()
    }

    /// True when the engine produced no matches.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }
}

/// GPU + CPU scan operations exposed by every matcher in this crate.
/// Object-safe (`dyn MatchScan` is valid) so consumers can hold a heap-
/// allocated trait object and swap engines at runtime.
pub trait MatchScan {
    /// GPU dispatch through a concrete backend, returning up to
    /// `max_matches` matches. Engines pre-allocate the hit buffer at
    /// `max_matches * 3 + 1` u32 slots; setting this too low silently
    /// truncates results.
    fn scan(
        &self,
        backend: &dyn VyreBackend,
        haystack: &[u8],
        max_matches: u32,
    ) -> Result<Vec<Match>, vyre::BackendError>;

    /// CPU reference scan. Used by the cross-layer parity tests in
    /// `vyre-conform`; engines that lack a meaningful CPU stepper
    /// (none today) can return an empty vec but should never fabricate
    /// results.
    fn scan_cpu(&self, haystack: &[u8]) -> Vec<Match>;

    /// Stable identity for cache filenames + telemetry. Engines hash
    /// their pattern set + version constant. Consumers pass this
    /// straight to [`cached_load_or_compile`] without further hashing.
    fn cache_key(&self) -> String;
}

/// Wire serialization for caching a compiled engine. Kept separate
/// from [`MatchScan`] because typed errors aren't dyn-safe.
pub trait MatchEngineCache: Sized {
    /// The engine's wire-error enum. Forwarded to the cache helper so
    /// load failures discriminate "stale cache, recompile" from "real
    /// bug, refuse to start".
    type WireError: std::fmt::Display + std::fmt::Debug;

    /// Wire-format magic the engine stamps on every encoded blob. The
    /// contracts test asserts that `to_bytes()[0..4] == WIRE_MAGIC`
    /// so consumers cannot accidentally forge a cache file with a
    /// different magic and have it silently load.
    const WIRE_MAGIC: [u8; 4];

    /// Wire-format version stamped after the magic. Bumped on any
    /// breaking layout change. The cache helper uses this to discard
    /// blobs from older builds; a `VersionMismatch` decode error is
    /// the canonical "stale cache, recompile" signal.
    const WIRE_VERSION: u32;

    /// Encode the compiled engine for on-disk caching.
    ///
    /// # Errors
    /// Engine-specific framing error.
    fn to_bytes(&self) -> Result<Vec<u8>, Self::WireError>;

    /// Decode a previously-cached engine.
    ///
    /// # Errors
    /// Engine-specific framing error. The cache helper treats every
    /// `WireError` as "stale, drop and recompile" — that's the
    /// designed-in semantics.
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::WireError>;
}

/// Resolve the cache file path for `cache_key` under `cache_dir`.
/// Creates `cache_dir` (and any missing parents) on first use. Returns
/// `None` when the directory could not be created — consumers should
/// fall through to a non-cached compile in that case.
pub fn cache_path(cache_dir: &Path, cache_key: &str) -> Option<PathBuf> {
    if !cache_dir.exists() && std::fs::create_dir_all(cache_dir).is_err() {
        return None;
    }
    Some(cache_dir.join(format!("{cache_key}.bin")))
}

/// Generic load-or-compile-and-save for any [`MatchEngineCache`].
///
/// Replaces the per-engine cache wiring keyhog (and any other consumer)
/// would otherwise duplicate. The contract:
///
///   - Cache hit: read the file, attempt `from_bytes`. On success
///     return the loaded engine. On framing error, delete the stale
///     blob and fall through.
///   - Cache miss / stale: call `compile`, `to_bytes`, atomically
///     write to a `.tmp.<pid>` sibling, rename onto the final path.
///   - Any save-side error is logged at `tracing::debug` and ignored —
///     a failed cache write must never break the scan path.
///
/// `compile` is `FnOnce` so consumers can move expensive captures
/// (pattern sources, file readers) into it without cloning.
pub fn cached_load_or_compile<E, F>(cache_dir: &Path, cache_key: &str, compile: F) -> E
where
    E: MatchEngineCache,
    F: FnOnce() -> E,
{
    let Some(path) = cache_path(cache_dir, cache_key) else {
        return compile();
    };

    if let Ok(bytes) = std::fs::read(&path) {
        match E::from_bytes(&bytes) {
            Ok(engine) => return engine,
            Err(_) => {
                // Stale or corrupt blob — best-effort delete and fall
                // through to recompile. Cache-side errors are silent
                // by design: a broken cache must never break the scan.
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    let engine = compile();
    if let Ok(bytes) = engine.to_bytes() {
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        if std::fs::write(&tmp, &bytes).is_ok() {
            // Best-effort rename. A crash here leaves either the old
            // cache (still valid) or no cache (recompile next run).
            let _ = std::fs::rename(&tmp, &path);
        }
    }
    engine
}

// ---- Concrete impls for the engines this crate ships ----

use crate::matching::literal_set::{GpuLiteralSet, LiteralSetWireError};

impl MatchScan for GpuLiteralSet {
    fn scan(
        &self,
        backend: &dyn VyreBackend,
        haystack: &[u8],
        max_matches: u32,
    ) -> Result<Vec<Match>, vyre::BackendError> {
        GpuLiteralSet::scan(self, backend, haystack, max_matches)
    }

    fn scan_cpu(&self, haystack: &[u8]) -> Vec<Match> {
        GpuLiteralSet::scan_cpu(self, haystack)
    }

    fn cache_key(&self) -> String {
        // Use vyre's FNV-1a primitive instead of std::DefaultHasher.
        // DefaultHasher's SipHash seed is randomized per process, so
        // cache files written by one run would never match keys
        // generated by the next — silently breaking the cache. FNV-1a
        // is deterministic, fast, and we don't need cryptographic
        // collision resistance for an identity hash.
        let mut buf: Vec<u8> = Vec::with_capacity(
            (self.pattern_offsets.len() + self.pattern_lengths.len() + self.pattern_bytes.len())
                * 4,
        );
        for w in &self.pattern_offsets {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        for w in &self.pattern_lengths {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        for w in &self.pattern_bytes {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        let h = vyre_primitives::hash::fnv1a::fnv1a64(&buf);
        format!("lit-{h:016x}")
    }
}

impl MatchEngineCache for GpuLiteralSet {
    type WireError = LiteralSetWireError;
    const WIRE_MAGIC: [u8; 4] = *b"VLIT";
    const WIRE_VERSION: u32 = 1;

    fn to_bytes(&self) -> Result<Vec<u8>, Self::WireError> {
        GpuLiteralSet::to_bytes(self)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::WireError> {
        GpuLiteralSet::from_bytes(bytes)
    }
}

#[cfg(feature = "matching-dfa")]
mod direct_gpu_impls {
    use super::*;
    use crate::matching::direct_gpu::DirectGpuScanner;

    impl MatchScan for DirectGpuScanner {
        fn scan(
            &self,
            backend: &dyn VyreBackend,
            haystack: &[u8],
            max_matches: u32,
        ) -> Result<Vec<Match>, vyre::BackendError> {
            DirectGpuScanner::scan(self, backend, haystack, max_matches)
        }

        fn scan_cpu(&self, haystack: &[u8]) -> Vec<Match> {
            DirectGpuScanner::scan_cpu(self, haystack)
        }

        fn cache_key(&self) -> String {
            // Direct scanner is a thin wrapper over a literal-set —
            // delegate so caches don't fork.
            format!("direct-gpu-{}", self.literal_set_cache_key())
        }
    }
}

#[cfg(feature = "matching-nfa")]
mod rule_pipeline_impls {
    use super::*;
    use crate::matching::mega_scan::{PipelineWireError, RulePipeline};

    impl MatchScan for RulePipeline {
        fn scan(
            &self,
            backend: &dyn VyreBackend,
            haystack: &[u8],
            max_matches: u32,
        ) -> Result<Vec<Match>, vyre::BackendError> {
            RulePipeline::scan(self, backend, haystack, max_matches)
        }

        fn scan_cpu(&self, haystack: &[u8]) -> Vec<Match> {
            RulePipeline::scan_cpu(self, haystack)
        }

        fn cache_key(&self) -> String {
            // Deterministic hash via vyre's FNV-1a primitive — see the
            // `GpuLiteralSet::cache_key` implementation for why
            // `DefaultHasher` is the wrong choice here (per-process
            // SipHash seed defeats persistent caching).
            let mut buf: Vec<u8> = Vec::with_capacity(
                8 + (self.transition_table.len() + self.epsilon_table.len()) * 4,
            );
            buf.extend_from_slice(&self.plan.num_states.to_le_bytes());
            buf.extend_from_slice(&self.plan.input_len.to_le_bytes());
            for w in &self.transition_table {
                buf.extend_from_slice(&w.to_le_bytes());
            }
            for w in &self.epsilon_table {
                buf.extend_from_slice(&w.to_le_bytes());
            }
            let h = vyre_primitives::hash::fnv1a::fnv1a64(&buf);
            format!("pipe-{h:016x}")
        }
    }

    impl MatchEngineCache for RulePipeline {
        type WireError = PipelineWireError;
        const WIRE_MAGIC: [u8; 4] = *b"VRPL";
        const WIRE_VERSION: u32 = 1;

        fn to_bytes(&self) -> Result<Vec<u8>, Self::WireError> {
            RulePipeline::to_bytes(self)
        }

        fn from_bytes(bytes: &[u8]) -> Result<Self, Self::WireError> {
            RulePipeline::from_bytes(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matching::literal_set::GpuLiteralSet;

    #[test]
    fn cache_key_changes_when_patterns_change() {
        let a = GpuLiteralSet::compile(&[b"AKIA".as_slice(), b"ghp_".as_slice()]);
        let b = GpuLiteralSet::compile(&[b"AKIA".as_slice(), b"ghp__".as_slice()]);
        assert_ne!(MatchScan::cache_key(&a), MatchScan::cache_key(&b));
    }

    #[test]
    fn cache_key_stable_for_same_patterns() {
        let a = GpuLiteralSet::compile(&[b"AKIA".as_slice(), b"ghp_".as_slice()]);
        let b = GpuLiteralSet::compile(&[b"AKIA".as_slice(), b"ghp_".as_slice()]);
        assert_eq!(MatchScan::cache_key(&a), MatchScan::cache_key(&b));
    }

    #[test]
    fn cached_helper_round_trips_via_disk() {
        let dir = tempfile::tempdir().unwrap();
        let key = "test-engine";
        let mut compiles = 0;
        let _engine: GpuLiteralSet = cached_load_or_compile(dir.path(), key, || {
            compiles += 1;
            GpuLiteralSet::compile(&[b"AKIA".as_slice()])
        });
        assert_eq!(compiles, 1);

        // Second call hits the disk cache; the closure must NOT run.
        let mut second_compiles = 0;
        let _engine2: GpuLiteralSet = cached_load_or_compile(dir.path(), key, || {
            second_compiles += 1;
            GpuLiteralSet::compile(&[b"AKIA".as_slice()])
        });
        assert_eq!(second_compiles, 0);
    }

    #[test]
    fn cached_helper_recompiles_on_corrupt_blob() {
        let dir = tempfile::tempdir().unwrap();
        let key = "test-corrupt";
        // Plant a corrupt blob.
        std::fs::write(dir.path().join(format!("{key}.bin")), b"not a real blob").unwrap();

        let mut compiles = 0;
        let _engine: GpuLiteralSet = cached_load_or_compile(dir.path(), key, || {
            compiles += 1;
            GpuLiteralSet::compile(&[b"AKIA".as_slice()])
        });
        assert_eq!(compiles, 1);
    }
}
