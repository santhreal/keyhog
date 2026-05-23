//! CUDA module cache: PTX text to loaded `CUfunction` lookup.

use std::cell::RefCell;
use std::hash::BuildHasherDefault;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use cudarc::driver::sys::{CUfunction, CUmodule, CUresult};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use rustc_hash::FxHasher;
use smallvec::SmallVec;
use vyre_driver::{BackendError, DispatchConfig};
use vyre_foundation::ir::Program;

use super::staging_reserve::reserve_vec;
use crate::backend::accounting::checked_sub_usize;

/// Soft cap on loaded CUDA modules. Eviction drops the cache to half-capacity.
const MODULE_CACHE_SOFT_CAP: usize = 256;
const MODULE_CACHE_RETAIN_AFTER_EVICTION: usize = MODULE_CACHE_SOFT_CAP / 2;
/// Soft cap on lowered PTX source strings retained before module loading.
const PTX_SOURCE_CACHE_SOFT_CAP: usize = 512;
const PTX_SOURCE_CACHE_RETAIN_AFTER_EVICTION: usize = PTX_SOURCE_CACHE_SOFT_CAP / 2;
const PTX_SOURCE_CACHE_SOFT_BYTES: usize = 256 * 1024 * 1024;
const PTX_SOURCE_CACHE_MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const PTX_LOWERING_CONTRACT: &[u8] =
    b"vyre-cuda-ptx-lowering-contract:v3:ssa-carrier-snapshots+no-mutable-loop-unroll";
static PTX_CACHE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static PTX_CSTR_SCRATCH: RefCell<Vec<u8>> = RefCell::new(Vec::new());
}

/// Stable key for one PTX module on one CUDA architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ModuleCacheKey(pub(crate) [u8; 32]);

/// Stable key for cached PTX source before CUDA module loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PtxSourceCacheKey([u8; 32]);

/// Cache of lowered PTX text. This sits in front of the CUDA module cache so
/// ordinary dispatches avoid re-running descriptor validation and PTX emission
/// before discovering that the module is already warm.
#[derive(Debug)]
pub(crate) struct CudaPtxSourceCache {
    sources: DashMap<PtxSourceCacheKey, CachedPtxSource, BuildHasherDefault<FxHasher>>,
    hits: AtomicU64,
    misses: AtomicU64,
    cached_source_bytes: AtomicUsize,
}

#[derive(Debug)]
struct CachedPtxSource {
    source: Arc<str>,
    source_bytes: usize,
    access_count: AtomicU32,
}

/// Snapshot of the CUDA PTX source cache used before driver module loading.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CudaPtxSourceCacheSnapshot {
    /// Number of normalized PTX source entries retained in memory.
    pub entries: usize,
    /// Number of PTX source bytes retained in memory.
    pub cached_source_bytes: usize,
    /// Number of lookups served from an existing lowered PTX source.
    pub hits: u64,
    /// Number of lookups that had to lower PTX source before insertion.
    pub misses: u64,
}

impl CudaPtxSourceCache {
    pub(crate) fn new() -> Self {
        Self {
            sources: DashMap::with_hasher(BuildHasherDefault::<FxHasher>::default()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            cached_source_bytes: AtomicUsize::new(0),
        }
    }

    pub(crate) fn key_for_program(
        &self,
        program: &Program,
        config: &DispatchConfig,
        ptx_target_sm: u32,
        subgroup_size: u32,
        feature_flags: vyre_driver::pipeline::PipelineFeatureFlags,
    ) -> Result<PtxSourceCacheKey, BackendError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PTX_LOWERING_CONTRACT);
        let normalized_digest = vyre_driver::pipeline::try_normalized_program_cache_digest(program)
            .map_err(|error| {
                BackendError::new(format!("CUDA PTX source cache digest failed: {error}"))
            })?;
        hasher.update(&normalized_digest);
        for lane in vyre_driver::program_vsa_fingerprint_words(program) {
            hasher.update(&lane.to_le_bytes());
        }
        vyre_driver::pipeline::update_dispatch_policy_cache_hash(&mut hasher, config);
        hasher.update(&ptx_target_sm.to_le_bytes());
        hasher.update(&subgroup_size.to_le_bytes());
        hasher.update(&feature_flags.bits().to_le_bytes());
        Ok(PtxSourceCacheKey(*hasher.finalize().as_bytes()))
    }

    pub(crate) fn get_or_lower(
        &self,
        key: PtxSourceCacheKey,
        lower: impl FnOnce() -> Result<String, BackendError>,
    ) -> Result<Arc<str>, BackendError> {
        if let Some(source) = self.sources.get(&key) {
            increment_cache_access_u32(&source.access_count, "CUDA PTX source access count");
            increment_cache_counter_u64(&self.hits, "CUDA PTX source cache hits");
            return Ok(Arc::clone(&source.value().source));
        }
        // Disk persistence: PTX text is large (megabytes) but compresses
        // well; reading from disk is ~10 ms vs the multi-100 ms cost of
        // re-running the vyre IR -> PTX lowering on the same program
        // shape. Cross-process and across-runs: second run of the same
        // corpus loads every lowered PTX from disk, hitting the CUDA
        // driver's cuda-jit cache for PTX -> cuBIN compilation, and
        // skipping the vyre-side lowering entirely.
        if let Some(disk_source) = load_ptx_from_disk(&key)? {
            let arc: Arc<str> = disk_source.into();
            return self.insert_disk_cached_source(key, arc);
        }
        increment_cache_counter_u64(&self.misses, "CUDA PTX source cache misses");
        if self.sources.len() >= PTX_SOURCE_CACHE_SOFT_CAP {
            self.evict_submodular();
        }
        let source = match self.sources.entry(key) {
            Entry::Occupied(existing) => {
                increment_cache_access_u32(
                    &existing.get().access_count,
                    "CUDA PTX source access count",
                );
                Arc::clone(&existing.get().source)
            }
            Entry::Vacant(entry) => {
                let source: Arc<str> = lower()?.into();
                store_ptx_to_disk(&key, source.as_ref())?;
                let source_bytes = source.len();
                if source_bytes > PTX_SOURCE_CACHE_SOFT_BYTES {
                    return Ok(source);
                }
                reserve_cached_source_bytes(&self.cached_source_bytes, source_bytes)?;
                entry.insert(CachedPtxSource {
                    source: Arc::clone(&source),
                    source_bytes,
                    access_count: AtomicU32::new(1),
                });
                source
            }
        };
        if self.cached_source_bytes.load(Ordering::Acquire) > PTX_SOURCE_CACHE_SOFT_BYTES {
            self.evict_submodular();
        }
        Ok(source)
    }

    pub(crate) fn clear(&self) {
        self.sources.clear();
        self.hits.store(0, Ordering::Release);
        self.misses.store(0, Ordering::Release);
        self.cached_source_bytes.store(0, Ordering::Release);
    }

    pub(crate) fn snapshot(&self) -> CudaPtxSourceCacheSnapshot {
        CudaPtxSourceCacheSnapshot {
            entries: self.sources.len(),
            cached_source_bytes: self.cached_source_bytes.load(Ordering::Acquire),
            hits: self.hits.load(Ordering::Acquire),
            misses: self.misses.load(Ordering::Acquire),
        }
    }

    fn insert_disk_cached_source(
        &self,
        key: PtxSourceCacheKey,
        source: Arc<str>,
    ) -> Result<Arc<str>, BackendError> {
        let source_bytes = source.len();
        if source_bytes > PTX_SOURCE_CACHE_SOFT_BYTES {
            return Ok(source);
        }
        let cached_source_bytes = self.cached_source_bytes.load(Ordering::Acquire);
        if self.sources.len() >= PTX_SOURCE_CACHE_SOFT_CAP
            || cached_source_bytes > PTX_SOURCE_CACHE_SOFT_BYTES - source_bytes
        {
            self.evict_submodular();
        }
        match self.sources.entry(key) {
            Entry::Occupied(existing) => {
                increment_cache_access_u32(
                    &existing.get().access_count,
                    "CUDA PTX source access count",
                );
                increment_cache_counter_u64(&self.hits, "CUDA PTX source cache disk hits");
                Ok(Arc::clone(&existing.get().source))
            }
            Entry::Vacant(entry) => {
                reserve_cached_source_bytes(&self.cached_source_bytes, source_bytes)?;
                entry.insert(CachedPtxSource {
                    source: Arc::clone(&source),
                    source_bytes,
                    access_count: AtomicU32::new(1),
                });
                increment_cache_counter_u64(&self.hits, "CUDA PTX source cache disk hits");
                Ok(source)
            }
        }
    }

    fn evict_submodular(&self) {
        let mut keys = SmallVec::<[PtxSourceCacheKey; PTX_SOURCE_CACHE_SOFT_CAP]>::new();
        let mut gains = SmallVec::<[u32; PTX_SOURCE_CACHE_SOFT_CAP]>::new();
        for entry in self.sources.iter() {
            keys.push(*entry.key());
            gains.push(entry.access_count.load(Ordering::Relaxed));
        }
        let Some((n, k)) = retention_problem_size(
            gains.len(),
            PTX_SOURCE_CACHE_RETAIN_AFTER_EVICTION,
            "CUDA PTX source cache",
        ) else {
            self.sources.clear();
            self.cached_source_bytes.store(0, Ordering::Release);
            vyre_driver::cache_eviction::record_eviction_counts(keys.len(), keys.len());
            return;
        };
        let retention =
            match vyre_driver::cache_eviction::try_select_retention_set(&mut gains, n, k) {
                Ok(retention) => retention,
                Err(error) => {
                    tracing::error!(
                    "CUDA PTX source cache eviction could not allocate retention state: {error}"
                );
                    self.sources.clear();
                    self.cached_source_bytes.store(0, Ordering::Release);
                    vyre_driver::cache_eviction::record_eviction_counts(keys.len(), keys.len());
                    return;
                }
            };

        let mut to_remove: SmallVec<[PtxSourceCacheKey; PTX_SOURCE_CACHE_SOFT_CAP]> =
            SmallVec::new();
        if let Err(error) = to_remove.try_reserve_exact(retention.len()) {
            tracing::error!(
                "CUDA PTX source cache eviction could not reserve {} removal key slot(s): {error}",
                retention.len()
            );
            self.sources.clear();
            self.cached_source_bytes.store(0, Ordering::Release);
            vyre_driver::cache_eviction::record_eviction_counts(keys.len(), keys.len());
            return;
        }
        for (i, retain) in retention.iter().enumerate() {
            if *retain == 0 {
                if let Some(key) = keys.get(i) {
                    to_remove.push(*key);
                }
            }
        }
        let dropped = to_remove.len();
        let total = keys.len().max(1);
        let mut dropped_bytes = 0usize;
        for key in &to_remove {
            if let Some((_, removed)) = self.sources.remove(key) {
                let Some(next) = dropped_bytes.checked_add(removed.source_bytes) else {
                    self.sources.clear();
                    self.cached_source_bytes.store(0, Ordering::Release);
                    vyre_driver::cache_eviction::record_eviction_counts(keys.len(), keys.len());
                    return;
                };
                dropped_bytes = next;
            }
        }
        if dropped_bytes != 0 {
            if release_cached_source_bytes(&self.cached_source_bytes, dropped_bytes).is_err() {
                self.sources.clear();
                self.cached_source_bytes.store(0, Ordering::Release);
                vyre_driver::cache_eviction::record_eviction_counts(keys.len(), keys.len());
                return;
            }
        }
        vyre_driver::cache_eviction::record_eviction_counts(dropped, total);
    }
}

fn reserve_cached_source_bytes(
    cached_source_bytes: &AtomicUsize,
    source_bytes: usize,
) -> Result<(), BackendError> {
    let mut observed = cached_source_bytes.load(Ordering::Acquire);
    loop {
        let next = observed.checked_add(source_bytes).ok_or_else(|| {
            BackendError::new(format!(
                "CUDA PTX source cache byte accounting overflowed while adding {source_bytes} bytes to {observed}. Fix: shard generated PTX or clear the source cache before inserting another artifact."
            ))
        })?;
        match cached_source_bytes.compare_exchange_weak(
            observed,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(actual) => observed = actual,
        }
    }
}

fn ptx_disk_cache_root() -> Result<PathBuf, BackendError> {
    if let Some(p) = std::env::var_os("VYRE_PTX_SOURCE_CACHE_DIR") {
        let path = PathBuf::from(p);
        if path.as_os_str().is_empty() {
            return Err(BackendError::new(
                "VYRE_PTX_SOURCE_CACHE_DIR is empty. Fix: set it to a writable persistent directory or unset it so XDG/HOME cache discovery can run."
                    .to_string(),
            ));
        }
        return Ok(path);
    }
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(xdg).join("vyre").join("ptx-source"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home)
            .join(".cache")
            .join("vyre")
            .join("ptx-source"));
    }
    Err(BackendError::new(
        "CUDA PTX source cache has no VYRE_PTX_SOURCE_CACHE_DIR, XDG_CACHE_HOME, or HOME. Fix: configure a writable persistent cache root; temporary fallback is forbidden for production compile performance."
            .to_string(),
    ))
}

fn retention_problem_size(
    len: usize,
    retain_after_eviction: usize,
    label: &str,
) -> Option<(u32, u32)> {
    let n = match u32::try_from(len) {
        Ok(value) => value,
        Err(source) => {
            tracing::error!("{label} retention candidate count cannot fit u32: {source}. Fix: lower cache soft caps or shard eviction telemetry.");
            return None;
        }
    };
    let k = match u32::try_from(retain_after_eviction) {
        Ok(value) => value,
        Err(source) => {
            tracing::error!("{label} retention target count cannot fit u32: {source}. Fix: lower cache soft caps or shard eviction telemetry.");
            return None;
        }
    };
    if k > n {
        tracing::error!("{label} retention target exceeds candidate count: retain={k}, candidates={n}. Fix: trigger eviction only after the cache reaches its soft cap or correct the retention policy.");
        return None;
    }
    Some((n, k))
}

fn ptx_disk_cache_path(key: &PtxSourceCacheKey) -> Result<PathBuf, BackendError> {
    let mut hex = [0u8; 64];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in key.0.iter().enumerate() {
        hex[i * 2] = HEX[usize::from(b >> 4)];
        hex[i * 2 + 1] = HEX[usize::from(b & 0x0f)];
    }
    let stem = std::str::from_utf8(&hex).map_err(|error| {
        BackendError::new(format!(
            "CUDA PTX source cache generated a non-UTF8 hex key from fixed lowercase ASCII digits: {error}. Fix: inspect cache key generation before publishing PTX artifacts."
        ))
    })?;
    let dir = ptx_disk_cache_root()?.join(&stem[..2]);
    Ok(dir.join(format!("{stem}.ptx")))
}

fn load_ptx_from_disk(key: &PtxSourceCacheKey) -> Result<Option<String>, BackendError> {
    let path = ptx_disk_cache_path(key)?;
    match std::fs::metadata(&path) {
        Ok(metadata) => {
            validate_ptx_disk_cache_file_len(metadata.len(), &path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(BackendError::new(format!(
                "failed to stat CUDA PTX source cache `{}`: {error}. Fix: repair cache file permissions or remove the corrupt cache entry; do not silently relower around a broken production cache.",
                path.display()
            )));
        }
    }
    match std::fs::read_to_string(&path) {
        Ok(source) => Ok(Some(source)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(BackendError::new(format!(
            "failed to read CUDA PTX source cache `{}`: {error}. Fix: repair cache file permissions or remove the corrupt cache entry; do not silently relower around a broken production cache.",
            path.display()
        ))),
    }
}

fn validate_ptx_disk_cache_file_len(
    byte_len: u64,
    path: &std::path::Path,
) -> Result<(), BackendError> {
    if byte_len > PTX_SOURCE_CACHE_MAX_ARTIFACT_BYTES {
        return Err(BackendError::new(format!(
            "CUDA PTX source cache `{}` is {byte_len} bytes, above the {} byte safety limit. Fix: remove the corrupt cache artifact or raise the artifact cap deliberately after reviewing compile-cache memory pressure.",
            path.display(),
            PTX_SOURCE_CACHE_MAX_ARTIFACT_BYTES
        )));
    }
    Ok(())
}

fn store_ptx_to_disk(key: &PtxSourceCacheKey, source: &str) -> Result<(), BackendError> {
    let source_len = u64::try_from(source.len()).map_err(|error| {
        BackendError::new(format!(
            "CUDA PTX source cache artifact length cannot fit u64: {error}. Fix: split the generated Program before attempting disk persistence."
        ))
    })?;
    if source_len > PTX_SOURCE_CACHE_MAX_ARTIFACT_BYTES {
        return Err(BackendError::new(format!(
            "refusing to write {} byte CUDA PTX source cache artifact above the {} byte safety limit. Fix: split the generated Program, reduce monomorphized PTX size, or raise the artifact cap deliberately after reviewing compile-cache memory pressure.",
            source_len,
            PTX_SOURCE_CACHE_MAX_ARTIFACT_BYTES
        )));
    }
    let path = ptx_disk_cache_path(key)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            BackendError::new(format!(
                "failed to create CUDA PTX source cache directory `{}`: {error}. Fix: set VYRE_PTX_SOURCE_CACHE_DIR to a writable cache directory or repair directory permissions.",
                parent.display()
            ))
        })?;
    }
    let tmp_id = allocate_ptx_cache_tmp_id()?;
    let tmp = path.with_extension(format!("ptx.{}.{}.tmp", std::process::id(), tmp_id));
    std::fs::write(&tmp, source.as_bytes()).map_err(|error| {
        BackendError::new(format!(
            "failed to write CUDA PTX source cache temp file `{}`: {error}. Fix: set VYRE_PTX_SOURCE_CACHE_DIR to a writable cache directory or repair filesystem permissions.",
            tmp.display()
        ))
    })?;
    std::fs::rename(&tmp, &path).map_err(|error| {
        let cleanup = match std::fs::remove_file(&tmp) {
            Ok(()) => String::new(),
            Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {
                String::new()
            }
            Err(cleanup_error) => {
                format!(" Temp cleanup also failed: {cleanup_error}. Fix: repair cache directory permissions and remove stale temp files.")
            }
        };
        BackendError::new(format!(
            "failed to publish CUDA PTX source cache `{}` from temp `{}`: {error}.{cleanup} Fix: repair cache directory permissions and filesystem atomic-rename support.",
            path.display(),
            tmp.display()
        ))
    })?;
    Ok(())
}

fn allocate_ptx_cache_tmp_id() -> Result<u64, BackendError> {
    let mut observed = PTX_CACHE_TMP_COUNTER.load(Ordering::Acquire);
    loop {
        let next = match observed.checked_add(1) {
            Some(next) => next,
            None => {
                tracing::error!(
                    "CUDA PTX source cache temp-file counter overflowed u64; rebasing sequence to keep disk cache publication alive. Fix: inspect unexpectedly high cache write churn."
                );
                1
            }
        };
        match PTX_CACHE_TMP_COUNTER.compare_exchange_weak(
            observed,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(observed),
            Err(actual) => observed = actual,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        allocate_ptx_cache_tmp_id, ptx_disk_cache_path, validate_ptx_disk_cache_file_len,
        CudaPtxSourceCache, PtxSourceCacheKey, PTX_CACHE_TMP_COUNTER,
        PTX_SOURCE_CACHE_MAX_ARTIFACT_BYTES,
    };
    use std::sync::atomic::Ordering;

    #[test]
    fn ptx_source_cache_snapshot_tracks_hits_misses_and_clear() {
        let cache = CudaPtxSourceCache::new();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ptx_source_cache_snapshot_tracks_hits_misses_and_clear");
        hasher.update(&std::process::id().to_le_bytes());
        hasher.update(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after Unix epoch")
                .as_nanos()
                .to_le_bytes(),
        );
        let key = PtxSourceCacheKey(*hasher.finalize().as_bytes());
        let disk_path = ptx_disk_cache_path(&key)
            .expect("Fix: PTX source cache path should resolve on the test host.");
        match std::fs::remove_file(&disk_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!(
                "failed to remove pre-existing PTX cache artifact `{}` before deterministic cache-counter test: {error}",
                disk_path.display()
            ),
        }

        let first = cache
            .get_or_lower(key, || Ok("cached-ptx-source".to_string()))
            .expect("first PTX source lowering should populate cache");
        let second = cache
            .get_or_lower(key, || panic!("cache hit must not relower PTX source"))
            .expect("second PTX source lookup should hit cache");

        assert!(Arc::ptr_eq(&first, &second));
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.entries, 1);
        assert_eq!(snapshot.cached_source_bytes, "cached-ptx-source".len());
        assert_eq!(snapshot.hits, 1);
        assert_eq!(snapshot.misses, 1);

        cache.clear();
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.entries, 0);
        assert_eq!(snapshot.cached_source_bytes, 0);
        assert_eq!(snapshot.hits, 0);
        assert_eq!(snapshot.misses, 0);

        let _ = std::fs::remove_file(disk_path);
    }

    #[test]
    fn ptx_disk_cache_rejects_oversized_artifact_before_reading() {
        let path = std::path::PathBuf::from("/tmp/vyre-oversized-ptx-cache-artifact.ptx");
        let error =
            validate_ptx_disk_cache_file_len(PTX_SOURCE_CACHE_MAX_ARTIFACT_BYTES + 1, &path)
                .expect_err("oversized PTX cache artifact must be rejected before allocation");

        let message = error.to_string();
        assert!(message.contains("above the"));
        assert!(message.contains("safety limit"));
        assert!(message.contains("remove the corrupt cache artifact"));
    }

    #[test]
    fn ptx_source_cache_temp_id_rebases_after_counter_overflow() {
        PTX_CACHE_TMP_COUNTER.store(u64::MAX, Ordering::Release);

        let id = allocate_ptx_cache_tmp_id().expect(
            "PTX temp-file id allocation must rebase instead of failing on counter overflow",
        );

        assert_eq!(id, u64::MAX);
        assert_eq!(PTX_CACHE_TMP_COUNTER.load(Ordering::Acquire), 1);
    }

    #[test]
    fn module_cache_eviction_buffers_fit_soft_cap_inline() {
        let source = include_str!("module_cache.rs");

        assert!(
            source.contains("SmallVec::<[PtxSourceCacheKey; PTX_SOURCE_CACHE_SOFT_CAP]>::new()")
                && source.contains("SmallVec::<[u32; PTX_SOURCE_CACHE_SOFT_CAP]>::new()")
                && source.contains("SmallVec<[PtxSourceCacheKey; PTX_SOURCE_CACHE_SOFT_CAP]>"),
            "Fix: PTX source cache eviction scans the full soft cap, so eviction scratch must fit the full cap inline instead of spilling at the retained-half capacity."
        );
        assert!(
            source.contains("SmallVec::<[ModuleCacheKey; MODULE_CACHE_SOFT_CAP]>::new()")
                && source.contains("SmallVec::<[u32; MODULE_CACHE_SOFT_CAP]>::new()")
                && source.contains("SmallVec<[ModuleCacheKey; MODULE_CACHE_SOFT_CAP]>"),
            "Fix: CUDA module cache eviction scans the full soft cap, so eviction scratch must fit the full cap inline instead of spilling at the retained-half capacity."
        );
        assert!(
            !source.contains(concat!("unwrap_or", "(u32::MAX)")),
            "Fix: CUDA module-cache eviction must not silently cap retention problem sizes; impossible oversize states should evict instead of feeding fake counts to the optimizer."
        );
        assert!(
            !source.contains(concat!("cached_source_bytes", "\n                    .fetch_add")),
            "Fix: CUDA PTX source-cache byte accounting must reserve with checked arithmetic, not unchecked atomic fetch_add."
        );
        assert!(
            !source.contains(concat!("dropped-byte", " accounting overflowed")),
            "Fix: CUDA PTX source-cache eviction byte accounting must repair cache state instead of panicking."
        );
        assert!(
            !source.contains(concat!("cached_source_bytes", "\n                .fetch_sub")),
            "Fix: CUDA PTX source-cache byte release must use checked arithmetic, not wrapping atomic fetch_sub."
        );
        assert!(
            !source.contains(concat!("PTX_CACHE_TMP_COUNTER", ".fetch_add")),
            "Fix: CUDA PTX source-cache temp ids must use checked atomic allocation, not wrapping fetch_add."
        );
        assert!(
            !source.contains(concat!("access_count", ".fetch_add")),
            "Fix: CUDA module/source cache eviction priority counters must use bounded updates instead of raw wrapping."
        );
        assert!(
            !source.contains(concat!("hits", ".fetch_add"))
                && !source.contains(concat!("misses", ".fetch_add")),
            "Fix: CUDA module/source cache hit-miss counters must use explicit rebase helpers instead of raw wrapping."
        );
        assert!(
            !source.contains(concat!("fn ptx_disk_cache_root", "() -> PathBuf")),
            "Fix: CUDA PTX source-cache root discovery must return typed errors instead of panicking."
        );
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("module-cache source must have production section before tests");
        assert!(
            !production.contains(concat!("panic", "!("))
                && !production.contains(concat!(".unwrap_or_else", "(|source|")),
            "Fix: CUDA module/PTX cache production eviction and counter paths must repair or return errors instead of panicking."
        );
        assert!(
            production.contains("increment_cache_counter_u64(&self.hits")
                && production.contains("increment_cache_access_u32(&source.access_count")
                && production.contains("rebasing sequence to keep disk cache publication alive")
                && production.contains("record_eviction_counts(keys.len(), keys.len())"),
            "Fix: CUDA module/PTX cache counters must not fail valid cache hits, and impossible eviction states must repair the cache."
        );
        assert!(
            !production.contains("fn eviction_ratio")
                && !production.contains("dropped as f64")
                && !production.contains("total.max(1) as f64"),
            "Fix: CUDA module/PTX cache eviction telemetry must use backend-neutral exact count accounting, not local lossy ratios."
        );
        assert!(
            production.contains("cache_eviction::try_select_retention_set")
                && !production.contains(concat!(
                    "cache_eviction::select_retention_set",
                    "(&mut gains"
                )),
            "Fix: CUDA module/PTX cache eviction must use the fallible backend-neutral selector on release paths."
        );
    }
}

/// Loaded CUDA module and its `main` entry function.
#[derive(Debug)]
struct CachedModule {
    module: CUmodule,
    main: CUfunction,
    access_count: AtomicU32,
}

// SAFETY: FFI to libcuda.so. Pointer args were validated by the matching alloc
// / store API; lifetimes are documented in the surrounding function.
// cuda_check (or matching CUresult guard) propagates non-success codes as
// BackendError.
unsafe impl Send for CachedModule {}
// SAFETY: FFI to libcuda.so. Pointer args were validated by the matching alloc
// / store API; lifetimes are documented in the surrounding function.
// cuda_check (or matching CUresult guard) propagates non-success codes as
// BackendError.
unsafe impl Sync for CachedModule {}

impl Drop for CachedModule {
    fn drop(&mut self) {
        if !self.module.is_null() {
            // SAFETY: the module pointer came from `cuModuleLoadData` and is
            // owned by this cache entry.
            unsafe {
                let result = cudarc::driver::sys::cuModuleUnload(self.module);
                if result != CUresult::CUDA_SUCCESS {
                    eprintln!(
                        "Fix: cuModuleUnload failed during CUDA module cache drop with {result:?}; ensure all launches using the module have completed."
                    );
                }
            }
        }
    }
}

/// Sharded CUDA module cache with lock-free hit counters.
#[derive(Debug)]
pub(crate) struct CudaModuleCache {
    modules: DashMap<ModuleCacheKey, CachedModule, BuildHasherDefault<FxHasher>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl CudaModuleCache {
    pub(crate) fn new() -> Self {
        Self {
            modules: DashMap::with_hasher(BuildHasherDefault::<FxHasher>::default()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub(crate) fn key_for_ptx(
        &self,
        ptx_src: &str,
        compute_capability: (u32, u32),
    ) -> ModuleCacheKey {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ptx_src.as_bytes());
        hasher.update(&compute_capability.0.to_le_bytes());
        hasher.update(&compute_capability.1.to_le_bytes());
        ModuleCacheKey(*hasher.finalize().as_bytes())
    }

    pub(crate) fn function_for_ptx(
        &self,
        ptx_src: &str,
        key: ModuleCacheKey,
        ptx_target_sm: u32,
    ) -> Result<CUfunction, BackendError> {
        if let Some(module) = self.modules.get(&key) {
            increment_cache_access_u32(&module.access_count, "CUDA module cache access count");
            increment_cache_counter_u64(&self.hits, "CUDA module cache hits");
            return Ok(module.main);
        }
        increment_cache_counter_u64(&self.misses, "CUDA module cache misses");

        if self.modules.len() >= MODULE_CACHE_SOFT_CAP {
            self.evict_submodular();
        }
        match self.modules.entry(key) {
            Entry::Occupied(existing) => {
                increment_cache_access_u32(
                    &existing.get().access_count,
                    "CUDA module cache access count",
                );
                increment_cache_counter_u64(&self.hits, "CUDA module cache hits");
                Ok(existing.get().main)
            }
            Entry::Vacant(entry) => {
                let loaded = load_module(ptx_src, ptx_target_sm)?;
                let main = loaded.main;
                entry.insert(loaded);
                Ok(main)
            }
        }
    }

    pub(crate) fn clear(&self) {
        self.modules.clear();
    }

    pub(crate) fn len(&self) -> usize {
        self.modules.len()
    }

    pub(crate) fn snapshot(&self) -> vyre_driver::pipeline::PipelineCacheSnapshot {
        vyre_driver::pipeline::PipelineCacheSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }

    fn evict_submodular(&self) {
        let mut keys = SmallVec::<[ModuleCacheKey; MODULE_CACHE_SOFT_CAP]>::new();
        let mut gains = SmallVec::<[u32; MODULE_CACHE_SOFT_CAP]>::new();
        for entry in self.modules.iter() {
            keys.push(*entry.key());
            gains.push(entry.access_count.load(Ordering::Relaxed));
        }
        let Some((n, k)) = retention_problem_size(
            gains.len(),
            MODULE_CACHE_RETAIN_AFTER_EVICTION,
            "CUDA module cache",
        ) else {
            self.modules.clear();
            vyre_driver::cache_eviction::record_eviction_counts(keys.len(), keys.len());
            return;
        };

        let retention =
            match vyre_driver::cache_eviction::try_select_retention_set(&mut gains, n, k) {
                Ok(retention) => retention,
                Err(error) => {
                    tracing::error!(
                        "CUDA module cache eviction could not allocate retention state: {error}"
                    );
                    self.modules.clear();
                    vyre_driver::cache_eviction::record_eviction_counts(keys.len(), keys.len());
                    return;
                }
            };

        let mut to_remove: SmallVec<[ModuleCacheKey; MODULE_CACHE_SOFT_CAP]> = SmallVec::new();
        if let Err(error) = to_remove.try_reserve_exact(retention.len()) {
            tracing::error!(
                "CUDA module cache eviction could not reserve {} removal key slot(s): {error}",
                retention.len()
            );
            self.modules.clear();
            vyre_driver::cache_eviction::record_eviction_counts(keys.len(), keys.len());
            return;
        }
        for (i, retain) in retention.iter().enumerate() {
            if *retain == 0 {
                if let Some(key) = keys.get(i) {
                    to_remove.push(*key);
                }
            }
        }
        let dropped = to_remove.len();
        let total = keys.len().max(1);
        for key in &to_remove {
            self.modules.remove(key);
        }
        vyre_driver::cache_eviction::record_eviction_counts(dropped, total);
    }
}

fn release_cached_source_bytes(
    cached_source_bytes: &AtomicUsize,
    dropped_bytes: usize,
) -> Result<(), BackendError> {
    checked_sub_usize(cached_source_bytes, dropped_bytes, |observed, dropped| {
        BackendError::new(format!(
                "CUDA PTX source-cache byte accounting underflowed while dropping {dropped} bytes from {observed}. Fix: clear the source cache and rebuild PTX cache residency from live entries."
            ))
    })
}

fn increment_cache_counter_u64(counter: &AtomicU64, label: &'static str) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.wrapping_add(1);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                if current == u64::MAX {
                    tracing::error!(
                        "{label} wrapped to zero. Fix: scrape CUDA cache telemetry before u64::MAX or shard the telemetry window."
                    );
                }
                return;
            }
            Err(observed) => current = observed,
        }
    }
}

fn increment_cache_access_u32(counter: &AtomicU32, label: &'static str) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = if current == u32::MAX {
            u32::MAX
        } else {
            current + 1
        };
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                if current == u32::MAX {
                    tracing::error!(
                        "{label} reached u32::MAX and is pinned for retention scoring. Fix: clear the CUDA cache or shard retention windows."
                    );
                }
                return;
            }
            Err(observed) => current = observed,
        }
    }
}

fn load_module(ptx_src: &str, ptx_target_sm: u32) -> Result<CachedModule, BackendError> {
    let mut module = std::ptr::null_mut();
    let mut func = std::ptr::null_mut();
    PTX_CSTR_SCRATCH.with(|scratch| {
        let mut ptx_c = scratch.borrow_mut();
        ptx_c.clear();
        let ptx_c_capacity = ptx_src
            .len()
            .checked_add(1)
            .ok_or_else(|| BackendError::new("CUDA module PTX C-string length overflowed usize. Fix: split generated PTX before module loading."))?;
        reserve_vec(
            &mut ptx_c,
            ptx_c_capacity,
            "cuda module PTX C-string scratch",
        )?;
        ptx_c.extend_from_slice(ptx_src.as_bytes());
        ptx_c.push(0);
        if let Some(dir) = std::env::var_os("VYRE_PTX_DUMP_ALL_DIR") {
            write_ptx_dump(dir, ptx_src, "VYRE_PTX_DUMP_ALL_DIR")?;
        }
        // SAFETY: FFI to libcuda.so. Pointer args were validated by the
        // matching alloc / store API; lifetimes are documented in the
        // surrounding function. cuda_check (or matching CUresult guard)
        // propagates non-success codes as BackendError.
        let res = unsafe {
            cudarc::driver::sys::cuModuleLoadData(&mut module, ptx_c.as_ptr().cast())
        };
        if res != CUresult::CUDA_SUCCESS {
            if let Some(dir) = std::env::var_os("VYRE_PTX_DUMP_DIR") {
                let path = write_ptx_dump(dir, ptx_src, "VYRE_PTX_DUMP_DIR")?;
                eprintln!("VYRE_PTX_DUMP: wrote failing PTX to {}", path.display());
            }
            return Err(BackendError::KernelCompileFailed {
                backend: crate::CUDA_BACKEND_ID.to_string(),
                compiler_message: format!(
                    "cuModuleLoadData failed with {res:?} for sm_{ptx_target_sm} and PTX length {} bytes. Fix: run the PTX smoke test for this Program and verify the live CUDA driver supports the emitted PTX ISA.",
                    ptx_src.len()
                ),
            });
        }
        Ok(())
    })?;
    // SAFETY: FFI to libcuda.so. Pointer args were validated by the matching
    // alloc / store API; lifetimes are documented in the surrounding function.
    // cuda_check (or matching CUresult guard) propagates non-success codes as
    // BackendError.
    unsafe {
        let func_name = b"main\0";
        let res =
            cudarc::driver::sys::cuModuleGetFunction(&mut func, module, func_name.as_ptr().cast());
        if res != CUresult::CUDA_SUCCESS {
            let unload_result = cudarc::driver::sys::cuModuleUnload(module);
            if unload_result != CUresult::CUDA_SUCCESS {
                eprintln!(
                    "Fix: cuModuleUnload failed after cuModuleGetFunction failure with {unload_result:?}; CUDA module cleanup may be incomplete."
                );
            }
            return Err(BackendError::KernelCompileFailed {
                backend: crate::CUDA_BACKEND_ID.to_string(),
                compiler_message: format!(
                    "cuModuleGetFunction(main) failed with {res:?} for sm_{ptx_target_sm}. Fix: ensure CUDA PTX emission still declares `.visible .entry main`."
                ),
            });
        }
    }
    Ok(CachedModule {
        module,
        main: func,
        access_count: AtomicU32::new(1),
    })
}

fn write_ptx_dump(
    dir: std::ffi::OsString,
    ptx_src: &str,
    env_name: &'static str,
) -> Result<std::path::PathBuf, BackendError> {
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).map_err(|error| BackendError::KernelCompileFailed {
        backend: crate::CUDA_BACKEND_ID.to_string(),
        compiler_message: format!(
            "{env_name} points at `{}` but the directory could not be created: {error}. Fix: choose a writable PTX dump directory or unset {env_name}.",
            dir.display()
        ),
    })?;
    let hash = blake3::hash(ptx_src.as_bytes());
    let path = dir.join(format!("ptx-{}.ptx", &hash.to_hex().as_str()[..16]));
    std::fs::write(&path, ptx_src).map_err(|error| BackendError::KernelCompileFailed {
        backend: crate::CUDA_BACKEND_ID.to_string(),
        compiler_message: format!(
            "{env_name} could not write PTX dump `{}`: {error}. Fix: choose a writable PTX dump directory or unset {env_name}.",
            path.display()
        ),
    })?;
    Ok(path)
}
