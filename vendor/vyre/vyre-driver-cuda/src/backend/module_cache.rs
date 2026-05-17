//! CUDA module cache: PTX text to loaded `CUfunction` lookup.

use std::cell::RefCell;
use std::hash::BuildHasherDefault;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use cudarc::driver::sys::{CUfunction, CUmodule, CUresult};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use rustc_hash::FxHasher;
use smallvec::SmallVec;
use vyre_driver::{BackendError, DispatchConfig};
use vyre_foundation::ir::Program;

/// Soft cap on loaded CUDA modules. Eviction drops the cache to half-capacity.
const MODULE_CACHE_SOFT_CAP: usize = 256;
const MODULE_CACHE_RETAIN_AFTER_EVICTION: usize = MODULE_CACHE_SOFT_CAP / 2;
/// Soft cap on lowered PTX source strings retained before module loading.
const PTX_SOURCE_CACHE_SOFT_CAP: usize = 512;
const PTX_SOURCE_CACHE_RETAIN_AFTER_EVICTION: usize = PTX_SOURCE_CACHE_SOFT_CAP / 2;

thread_local! {
    static PTX_CSTR_SCRATCH: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(64 * 1024));
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
}

#[derive(Debug)]
struct CachedPtxSource {
    source: Arc<str>,
    access_count: AtomicU32,
}

/// Snapshot of the CUDA PTX source cache used before driver module loading.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CudaPtxSourceCacheSnapshot {
    /// Number of normalized PTX source entries retained in memory.
    pub entries: usize,
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
        }
    }

    pub(crate) fn key_for_program(
        &self,
        program: &Program,
        config: &DispatchConfig,
        ptx_target_sm: u32,
        subgroup_size: u32,
        feature_flags: vyre_driver::pipeline::PipelineFeatureFlags,
    ) -> PtxSourceCacheKey {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&vyre_driver::pipeline::normalized_program_cache_digest(
            program,
        ));
        for lane in vyre_driver::program_vsa_fingerprint_words(program) {
            hasher.update(&lane.to_le_bytes());
        }
        vyre_driver::pipeline::update_dispatch_policy_cache_hash(&mut hasher, config);
        hasher.update(&ptx_target_sm.to_le_bytes());
        hasher.update(&subgroup_size.to_le_bytes());
        hasher.update(&feature_flags.bits().to_le_bytes());
        PtxSourceCacheKey(*hasher.finalize().as_bytes())
    }

    pub(crate) fn get_or_lower(
        &self,
        key: PtxSourceCacheKey,
        lower: impl FnOnce() -> Result<String, BackendError>,
    ) -> Result<Arc<str>, BackendError> {
        if let Some(source) = self.sources.get(&key) {
            source.access_count.fetch_add(1, Ordering::Relaxed);
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Arc::clone(&source.value().source));
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        if self.sources.len() >= PTX_SOURCE_CACHE_SOFT_CAP {
            self.evict_submodular();
        }
        match self.sources.entry(key) {
            Entry::Occupied(existing) => {
                existing.get().access_count.fetch_add(1, Ordering::Relaxed);
                self.hits.fetch_add(1, Ordering::Relaxed);
                Ok(Arc::clone(&existing.get().source))
            }
            Entry::Vacant(entry) => {
                let source: Arc<str> = lower()?.into();
                entry.insert(CachedPtxSource {
                    source: Arc::clone(&source),
                    access_count: AtomicU32::new(1),
                });
                Ok(source)
            }
        }
    }

    pub(crate) fn clear(&self) {
        self.sources.clear();
        self.hits.store(0, Ordering::Release);
        self.misses.store(0, Ordering::Release);
    }

    pub(crate) fn snapshot(&self) -> CudaPtxSourceCacheSnapshot {
        CudaPtxSourceCacheSnapshot {
            entries: self.sources.len(),
            hits: self.hits.load(Ordering::Acquire),
            misses: self.misses.load(Ordering::Acquire),
        }
    }

    fn evict_submodular(&self) {
        let keys: SmallVec<[PtxSourceCacheKey; PTX_SOURCE_CACHE_RETAIN_AFTER_EVICTION]> =
            self.sources.iter().map(|entry| *entry.key()).collect();
        let mut gains: SmallVec<[u32; PTX_SOURCE_CACHE_RETAIN_AFTER_EVICTION]> = keys
            .iter()
            .map(|key| {
                self.sources
                    .get(key)
                    .map(|source| source.access_count.load(Ordering::Relaxed))
                    .unwrap_or(0)
            })
            .collect();
        let n = u32::try_from(gains.len()).unwrap_or(u32::MAX);
        let k = u32::try_from(PTX_SOURCE_CACHE_RETAIN_AFTER_EVICTION.min(gains.len()))
            .unwrap_or(u32::MAX);
        let retention = vyre_driver::cache_eviction::select_retention_set(&mut gains, n, k);

        let mut to_remove: SmallVec<[PtxSourceCacheKey; PTX_SOURCE_CACHE_RETAIN_AFTER_EVICTION]> =
            SmallVec::new();
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
            self.sources.remove(key);
        }
        vyre_driver::cache_eviction::record_eviction(dropped as f64 / total as f64);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{CudaPtxSourceCache, PtxSourceCacheKey};

    #[test]
    fn ptx_source_cache_snapshot_tracks_hits_misses_and_clear() {
        let cache = CudaPtxSourceCache::new();
        let key = PtxSourceCacheKey([7; 32]);

        let first = cache
            .get_or_lower(key, || Ok("cached-ptx-source".to_string()))
            .expect("first PTX source lowering should populate cache");
        let second = cache
            .get_or_lower(key, || panic!("cache hit must not relower PTX source"))
            .expect("second PTX source lookup should hit cache");

        assert!(Arc::ptr_eq(&first, &second));
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.entries, 1);
        assert_eq!(snapshot.hits, 1);
        assert_eq!(snapshot.misses, 1);

        cache.clear();
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.entries, 0);
        assert_eq!(snapshot.hits, 0);
        assert_eq!(snapshot.misses, 0);
    }
}

/// Loaded CUDA module and its `main` entry function.
#[derive(Debug)]
struct CachedModule {
    module: CUmodule,
    main: CUfunction,
    access_count: AtomicU32,
}

unsafe impl Send for CachedModule {}
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
            module.access_count.fetch_add(1, Ordering::Relaxed);
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(module.main);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);

        if self.modules.len() >= MODULE_CACHE_SOFT_CAP {
            self.evict_submodular();
        }
        match self.modules.entry(key) {
            Entry::Occupied(existing) => {
                existing.get().access_count.fetch_add(1, Ordering::Relaxed);
                self.hits.fetch_add(1, Ordering::Relaxed);
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
        let keys: SmallVec<[ModuleCacheKey; MODULE_CACHE_RETAIN_AFTER_EVICTION]> =
            self.modules.iter().map(|entry| *entry.key()).collect();
        let mut gains: SmallVec<[u32; MODULE_CACHE_RETAIN_AFTER_EVICTION]> = keys
            .iter()
            .map(|key| {
                self.modules
                    .get(key)
                    .map(|module| module.access_count.load(Ordering::Relaxed))
                    .unwrap_or(0)
            })
            .collect();
        let n = u32::try_from(gains.len()).unwrap_or(u32::MAX);
        let k =
            u32::try_from(MODULE_CACHE_RETAIN_AFTER_EVICTION.min(gains.len())).unwrap_or(u32::MAX);

        let retention = vyre_driver::cache_eviction::select_retention_set(&mut gains, n, k);

        let mut to_remove: SmallVec<[ModuleCacheKey; 128]> = SmallVec::new();
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
        vyre_driver::cache_eviction::record_eviction(dropped as f64 / total as f64);
    }
}

fn load_module(ptx_src: &str, ptx_target_sm: u32) -> Result<CachedModule, BackendError> {
    let mut module = std::ptr::null_mut();
    let mut func = std::ptr::null_mut();
    PTX_CSTR_SCRATCH.with(|scratch| {
        let mut ptx_c = scratch.borrow_mut();
        ptx_c.clear();
        ptx_c.reserve(ptx_src.len() + 1);
        ptx_c.extend_from_slice(ptx_src.as_bytes());
        ptx_c.push(0);
        if let Some(dir) = std::env::var_os("VYRE_PTX_DUMP_ALL_DIR") {
            write_ptx_dump(dir, ptx_src, "VYRE_PTX_DUMP_ALL_DIR")?;
        }
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
