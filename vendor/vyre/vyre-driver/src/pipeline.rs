//! Pipeline mode — pre-compile a Program once, dispatch repeatedly with new inputs.
//!
//! P-6 from `docs/audits/ROADMAP_PERFORMANCE.md`. Trait-additive: backends
//! that genuinely cache compiled state override [`VyreBackend::compile_native`];
//! everything else gets a transparent passthrough whose [`CompiledPipeline::dispatch`]
//! is bit-identical to calling [`VyreBackend::dispatch`] directly.
//!
//! Use:
//!
//! ```no_run
//! use std::sync::Arc;
//! use vyre::{Program, VyreBackend, DispatchConfig};
//!
//! # fn example(backend: Arc<dyn VyreBackend>, program: &Program) -> Result<(), vyre::BackendError> {
//! let pipeline = vyre::pipeline::compile(backend, program, &DispatchConfig::default())?;
//! for inputs in std::iter::repeat(vec![vec![0u8; 64]]).take(1000) {
//!     let _outputs = pipeline.dispatch(&inputs, &DispatchConfig::default())?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Backends with native caches skip per-dispatch shader compilation,
//! pipeline-layout creation, and bind-group-layout creation. Per the
//! roadmap, this removes ~90% of per-call overhead on `wgpu`.
//!
//! # G8 — content-hash on-disk cache extension (planned)
//!
//! G8 adds an on-disk blob cache keyed by
//! `blake3(program.to_wire() || driver_version || device_gen ||
//! CURRENT_PIPELINE_CACHE_KEY_VERSION)` stored at
//! `~/.cache/vyre/pipelines/{hex}.bin`. Hit = skip compile, load
//! SPIR-V/PTX straight into a pipeline handle (single-digit ms
//! cold-start after the first run). Miss = compile as today, write
//! the blob. Key-version bump invalidates the on-disk cache the same
//! way it already invalidates in-memory keys. Lands as a new
//! `cache::on_disk::{load, store}` submodule; `compile()` signature
//! unchanged.

use std::sync::Arc;

use crate::backend::{BackendError, CompiledPipeline, DispatchConfig, VyreBackend};
use vyre_foundation::ir::Program;
use vyre_spec::BackendId;

/// Pipeline-cache key version.
///
/// Bumping `CURRENT_PIPELINE_CACHE_KEY_VERSION` invalidates every cached
/// pipeline without an API break. Backends embed the version in every
/// key they construct; a lookup against a key built by a different
/// version simply misses.
pub const CURRENT_PIPELINE_CACHE_KEY_VERSION: u32 = 1;

/// Capability bits that participate in pipeline-cache identity.
///
/// Two otherwise-identical pipelines compiled with different
/// `PipelineFeatureFlags` produce different cache keys — a pipeline
/// that assumed subgroup-op support cannot be reused on an adapter
/// that does not expose subgroup ops even if the shader bytes match.
///
/// Encoded as a bitfield so the wire form is compact and trivially
/// hashable. Bits `0x01..0x80` are v0.6 terminal; bits `0x100 ..`
/// reserved for future flags (0.7 backends are additive).
#[derive(
    Copy, Clone, Debug, Default, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct PipelineFeatureFlags(pub u32);

impl PipelineFeatureFlags {
    /// Pipeline was compiled against a lowering that emits subgroup /
    /// wave intrinsics.
    pub const SUBGROUP_OPS: Self = Self(1 << 0);
    /// Pipeline was compiled with native `f16` support.
    pub const F16: Self = Self(1 << 1);
    /// Pipeline was compiled with native `bf16` support.
    pub const BF16: Self = Self(1 << 2);
    /// Pipeline was compiled with tensor-core / matrix-engine
    /// intrinsics enabled.
    pub const TENSOR_CORES: Self = Self(1 << 3);
    /// Pipeline expects an async-compute queue at dispatch time.
    pub const ASYNC_COMPUTE: Self = Self(1 << 4);
    /// Pipeline expects push-constant support at dispatch time.
    pub const PUSH_CONSTANTS: Self = Self(1 << 5);
    /// Pipeline emits indirect-dispatch commands.
    pub const INDIRECT_DISPATCH: Self = Self(1 << 6);

    /// Empty flag set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Contains at least every bit of `other`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Union of two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Raw bit representation.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// Versioned pipeline-cache key shared by every backend.
///
/// Replaces the pre-0.6 pattern of using a raw blake3 hash as the key.
/// A raw hash is not robust: two pipelines that should miss (different
/// bind-group layout, different push-constant size, different
/// workgroup-size selection) hashed identically because the hash
/// covered the shader source only. Silent cache hits against a
/// non-equivalent pipeline are a correctness hazard (wrong bind-group
/// layout binds undefined data; wrong workgroup-size launches beyond
/// guarantees).
///
/// `#[non_exhaustive]` is enforced at the type level via the private
/// `__phantom` field: external callers construct keys through
/// [`PipelineCacheKey::new`] and cannot match exhaustively, so adding
/// a field in 0.7 does not break downstream matches.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PipelineCacheKey {
    /// Key format version. Bumped to invalidate every cache entry
    /// without an API break.
    pub version: u32,
    /// blake3 hash of the canonical shader source bytes (or AST bytes
    /// once the emitter lands — the hash covers whatever bytes the
    /// backend uses as its pipeline source).
    pub shader_hash: [u8; 32],
    /// Structural hash of the bind-group layout descriptors. Not the
    /// wgpu handle; the bytes that describe slot count, types,
    /// visibility, and access modes per bind group.
    pub bind_group_layout_hash: [u8; 32],
    /// Push-constant range in bytes. Included so a pipeline compiled
    /// for 16 B push constants never reuses against a layout that
    /// expects 32 B.
    pub push_constant_size: u32,
    /// Workgroup-size `[x, y, z]` the pipeline was specialized for.
    pub workgroup_size: [u32; 3],
    /// Feature-flag bits the pipeline assumes at dispatch time.
    pub feature_flags: PipelineFeatureFlags,
    /// Backend identity. Prevents wgpu and CUDA pipelines from
    /// colliding when they happen to produce identical shader hashes.
    pub backend_id: BackendId,
    /// Reserved private field so `PipelineCacheKey` cannot be
    /// constructed by structural literal (forward-compatibility lever).
    #[allow(dead_code)]
    __phantom: core::marker::PhantomData<()>,
}

impl PipelineCacheKey {
    /// Construct a key at the current version.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shader_hash: [u8; 32],
        bind_group_layout_hash: [u8; 32],
        push_constant_size: u32,
        workgroup_size: [u32; 3],
        feature_flags: PipelineFeatureFlags,
        backend_id: BackendId,
    ) -> Self {
        Self {
            version: CURRENT_PIPELINE_CACHE_KEY_VERSION,
            shader_hash,
            bind_group_layout_hash,
            push_constant_size,
            workgroup_size,
            feature_flags,
            backend_id,
            __phantom: core::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod pipeline_cache_key_tests {
    use super::*;

    fn hash32(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn different_workgroup_size_differs() {
        let a = PipelineCacheKey::new(
            hash32(1),
            hash32(2),
            0,
            [64, 1, 1],
            PipelineFeatureFlags::empty(),
            BackendId::from("wgpu"),
        );
        let b = PipelineCacheKey::new(
            hash32(1),
            hash32(2),
            0,
            [128, 1, 1],
            PipelineFeatureFlags::empty(),
            BackendId::from("wgpu"),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn different_feature_flags_differ() {
        let a = PipelineCacheKey::new(
            hash32(1),
            hash32(2),
            0,
            [1, 1, 1],
            PipelineFeatureFlags::empty(),
            BackendId::from("wgpu"),
        );
        let b = PipelineCacheKey::new(
            hash32(1),
            hash32(2),
            0,
            [1, 1, 1],
            PipelineFeatureFlags::SUBGROUP_OPS,
            BackendId::from("wgpu"),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn different_backend_id_differs() {
        let a = PipelineCacheKey::new(
            hash32(1),
            hash32(2),
            0,
            [1, 1, 1],
            PipelineFeatureFlags::empty(),
            BackendId::from("wgpu"),
        );
        let b = PipelineCacheKey::new(
            hash32(1),
            hash32(2),
            0,
            [1, 1, 1],
            PipelineFeatureFlags::empty(),
            BackendId::from("cuda"),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn flag_containment_is_correct() {
        let a = PipelineFeatureFlags::SUBGROUP_OPS.union(PipelineFeatureFlags::F16);
        assert!(a.contains(PipelineFeatureFlags::SUBGROUP_OPS));
        assert!(a.contains(PipelineFeatureFlags::F16));
        assert!(!a.contains(PipelineFeatureFlags::TENSOR_CORES));
    }

    #[test]
    fn version_is_current() {
        let k = PipelineCacheKey::new(
            hash32(1),
            hash32(2),
            0,
            [1, 1, 1],
            PipelineFeatureFlags::empty(),
            BackendId::from("wgpu"),
        );
        assert_eq!(k.version, CURRENT_PIPELINE_CACHE_KEY_VERSION);
    }
}

/// Compile `program` into a reusable pipeline using `backend`.
///
/// Behaviour:
/// - If the backend overrides [`VyreBackend::compile_native`] and returns
///   `Some`, the native pipeline is returned (full caching benefit).
/// - Otherwise a passthrough pipeline is returned that re-runs
///   [`VyreBackend::dispatch`] on every call. Semantics are identical;
///   no perf benefit.
///
/// Callers that want a uniform repeated-dispatch API regardless of which
/// backend they're talking to should always go through this function rather
/// than calling `backend.dispatch` themselves.
///
/// # Errors
///
/// Returns [`BackendError`] propagated from [`VyreBackend::compile_native`]
/// if the backend's native compile fails.
pub fn compile(
    backend: Arc<dyn VyreBackend>,
    program: &Program,
    config: &DispatchConfig,
) -> Result<Arc<dyn CompiledPipeline>, BackendError> {
    compile_shared(backend, Arc::new(program.clone()), config)
}

/// Compile an already shared `program` into a reusable pipeline.
///
/// This avoids cloning the program when callers already keep their IR in an
/// [`Arc`]. See [`compile`] for behavior and error semantics.
pub fn compile_shared(
    backend: Arc<dyn VyreBackend>,
    program: Arc<Program>,
    config: &DispatchConfig,
) -> Result<Arc<dyn CompiledPipeline>, BackendError> {
    if let Some(message) = program.top_level_region_violation() {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: megakernel/runtime admission requires a top-level Region-wrapped Program. {message}"
            ),
        });
    }
    if let Some(native) = backend.compile_native(&program, config)? {
        return Ok(native);
    }
    Ok(Arc::new(PassthroughPipeline {
        id: format!("{}:passthrough", backend.id()),
        backend,
        program,
        compile_config: config.clone(),
    }))
}

/// Default pipeline — re-runs the full backend `dispatch` on every call.
///
/// Used when a backend does not override `compile_native`. Provides the
/// same `CompiledPipeline` API surface so callers can be backend-agnostic,
/// but offers no caching benefit. Backends that compile shaders / pipelines
/// / bind-group layouts SHOULD override `compile_native` to skip those
/// per-call costs.
struct PassthroughPipeline {
    id: String,
    backend: Arc<dyn VyreBackend>,
    program: Arc<Program>,
    compile_config: DispatchConfig,
}

impl crate::backend::private::Sealed for PassthroughPipeline {}

impl CompiledPipeline for PassthroughPipeline {
    fn id(&self) -> &str {
        &self.id
    }

    fn dispatch(
        &self,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        // A non-default per-dispatch config takes precedence over the
        // compile-time config so callers can vary the dispatch profile
        // without recompiling. Backends with native caches make the same
        // choice — see WgpuPipeline in `vyre-wgpu`.
        let effective = if *config == DispatchConfig::default() {
            &self.compile_config
        } else {
            config
        };
        self.backend.dispatch(&self.program, inputs, effective)
    }

    fn dispatch_borrowed(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let effective = if *config == DispatchConfig::default() {
            &self.compile_config
        } else {
            config
        };
        self.backend
            .dispatch_borrowed(&self.program, inputs, effective)
    }
}

/// G8: content-hash on-disk pipeline cache.
///
/// Keyed by `blake3(program.to_wire() || driver_version || device_gen
/// || CURRENT_PIPELINE_CACHE_KEY_VERSION || feature_flags)`. A hit
/// lets a backend skip SPIR-V / PTX compilation and load the bytes
/// straight into a pipeline handle — single-digit ms cold start
/// after the first run.
///
/// This module owns the **pure** key derivation + blob I/O. The
/// backend supplies the blob bytes (its own SPIR-V / PTX /
/// metal-lib) and calls [`store`] after a successful compile;
/// subsequent runs call [`load`] before compiling. The key
/// versioning means a `CURRENT_PIPELINE_CACHE_KEY_VERSION` bump
/// invalidates every existing file on disk, the same way it
/// already invalidates in-memory keys.
pub mod on_disk {
    use std::fmt::Write as _;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    use blake3::Hasher;
    use vyre_foundation::ir::Program;

    use super::{PipelineFeatureFlags, CURRENT_PIPELINE_CACHE_KEY_VERSION};

    /// Cache-file extension. Binary blob.
    pub const CACHE_EXTENSION: &str = "bin";

    /// Compute the 32-byte blake3 cache key for `program` on the
    /// named backend.
    ///
    /// `driver_version` is the backend's own build identifier
    /// (e.g. wgpu's `WGPU_VERSION` constant); `device_gen` is a
    /// caller-chosen generation bucket for the target GPU family
    /// (e.g. `"ada-sm89"`, `"rdna3-gfx1100"`). Mixing them makes a
    /// pipeline compiled for Ada miss when the process runs on
    /// RDNA3, even though the Program bytes match.
    #[must_use]
    pub fn compute_cache_key(
        program_wire: &[u8],
        backend_id: &str,
        driver_version: &str,
        device_gen: &str,
        feature_flags: PipelineFeatureFlags,
    ) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&CURRENT_PIPELINE_CACHE_KEY_VERSION.to_le_bytes());
        hasher.update(&(backend_id.len() as u32).to_le_bytes());
        hasher.update(backend_id.as_bytes());
        hasher.update(&(driver_version.len() as u32).to_le_bytes());
        hasher.update(driver_version.as_bytes());
        hasher.update(&(device_gen.len() as u32).to_le_bytes());
        hasher.update(device_gen.as_bytes());
        hasher.update(&feature_flags.0.to_le_bytes());
        hasher.update(&(program_wire.len() as u64).to_le_bytes());
        hasher.update(program_wire);
        let mut out = [0_u8; 32];
        out.copy_from_slice(hasher.finalize().as_bytes());
        out
    }

    /// Convenience wrapper: computes the wire form of `program`
    /// via `Program::to_wire` before hashing.
    pub fn compute_cache_key_for(
        program: &Program,
        backend_id: &str,
        driver_version: &str,
        device_gen: &str,
        feature_flags: PipelineFeatureFlags,
    ) -> Result<[u8; 32], CacheError> {
        let wire = program
            .to_wire()
            .map_err(|e| CacheError::Wire(e.to_string()))?;
        Ok(compute_cache_key(
            &wire,
            backend_id,
            driver_version,
            device_gen,
            feature_flags,
        ))
    }

    /// Default cache root — `${XDG_CACHE_HOME:-$HOME/.cache}/vyre/pipelines`.
    ///
    /// Returns `None` when no home directory is resolvable (e.g. a
    /// sandbox with `HOME` unset). Callers that still want caching
    /// in that case must pass their own path to [`load`] / [`store`].
    #[must_use]
    pub fn default_cache_dir() -> Option<PathBuf> {
        let xdg = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from);
        if let Some(x) = xdg {
            return Some(x.join("vyre").join("pipelines"));
        }
        let home = std::env::var_os("HOME").map(PathBuf::from)?;
        Some(home.join(".cache").join("vyre").join("pipelines"))
    }

    /// Filename inside `cache_dir` for `key` — lowercase hex +
    /// `.bin` extension. Deterministic; no salt.
    #[must_use]
    pub fn cache_path(cache_dir: &Path, key: &[u8; 32]) -> PathBuf {
        // Writes to a String never fail; ignore the Result per the
        // stdlib convention for `fmt::Write` on owned buffers.
        let mut name = String::with_capacity(64 + 1 + CACHE_EXTENSION.len());
        for b in key {
            let _ = write!(&mut name, "{b:02x}");
        }
        name.push('.');
        name.push_str(CACHE_EXTENSION);
        cache_dir.join(name)
    }

    /// Load a cached blob by key. Returns `Ok(None)` on a miss
    /// (file doesn't exist) and `Err` on I/O errors.
    pub fn load(cache_dir: &Path, key: &[u8; 32]) -> Result<Option<Vec<u8>>, CacheError> {
        let path = cache_path(cache_dir, key);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(CacheError::Io { path, source: e }),
        }
    }

    /// Write a cached blob for `key`. Creates `cache_dir` if
    /// missing. Writes via a temp file + atomic rename so a
    /// concurrent reader either sees the old blob or the new one,
    /// never a torn write.
    pub fn store(cache_dir: &Path, key: &[u8; 32], bytes: &[u8]) -> Result<(), CacheError> {
        fs::create_dir_all(cache_dir).map_err(|e| CacheError::Io {
            path: cache_dir.to_path_buf(),
            source: e,
        })?;
        let final_path = cache_path(cache_dir, key);
        let tmp_path = final_path.with_extension("bin.tmp");
        fs::write(&tmp_path, bytes).map_err(|e| CacheError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;
        fs::rename(&tmp_path, &final_path).map_err(|e| CacheError::Io {
            path: final_path,
            source: e,
        })
    }

    /// Cache I/O errors.
    #[derive(Debug, thiserror::Error)]
    pub enum CacheError {
        #[error(
            "Fix: pipeline-cache I/O failed at {path:?}. \
             Ensure the cache directory is writable: {source}"
        )]
        Io {
            path: PathBuf,
            #[source]
            source: io::Error,
        },
        #[error(
            "Fix: program.to_wire() failed while computing cache key. \
             The Program is malformed; run the validator before caching. Inner: {0}"
        )]
        Wire(String),
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn key1() -> [u8; 32] {
            [1_u8; 32]
        }

        fn key2() -> [u8; 32] {
            [2_u8; 32]
        }

        #[test]
        fn compute_cache_key_is_deterministic() {
            let a = compute_cache_key(
                b"bytes",
                "wgpu",
                "v24",
                "ada",
                PipelineFeatureFlags::SUBGROUP_OPS,
            );
            let b = compute_cache_key(
                b"bytes",
                "wgpu",
                "v24",
                "ada",
                PipelineFeatureFlags::SUBGROUP_OPS,
            );
            assert_eq!(a, b);
        }

        #[test]
        fn compute_cache_key_changes_with_driver_version() {
            let a = compute_cache_key(b"x", "wgpu", "v24", "ada", PipelineFeatureFlags::empty());
            let b = compute_cache_key(b"x", "wgpu", "v25", "ada", PipelineFeatureFlags::empty());
            assert_ne!(a, b);
        }

        #[test]
        fn compute_cache_key_changes_with_device_gen() {
            let a = compute_cache_key(b"x", "wgpu", "v24", "ada", PipelineFeatureFlags::empty());
            let b = compute_cache_key(b"x", "wgpu", "v24", "rdna3", PipelineFeatureFlags::empty());
            assert_ne!(a, b);
        }

        #[test]
        fn compute_cache_key_changes_with_feature_flags() {
            let a = compute_cache_key(b"x", "wgpu", "v24", "ada", PipelineFeatureFlags::empty());
            let b = compute_cache_key(
                b"x",
                "wgpu",
                "v24",
                "ada",
                PipelineFeatureFlags::SUBGROUP_OPS,
            );
            assert_ne!(a, b);
        }

        #[test]
        fn compute_cache_key_changes_with_program_bytes() {
            let a = compute_cache_key(
                b"prog-a",
                "wgpu",
                "v24",
                "ada",
                PipelineFeatureFlags::empty(),
            );
            let b = compute_cache_key(
                b"prog-b",
                "wgpu",
                "v24",
                "ada",
                PipelineFeatureFlags::empty(),
            );
            assert_ne!(a, b);
        }

        #[test]
        fn compute_cache_key_not_vulnerable_to_length_extension() {
            // A naive concatenation of two variable-length fields
            // without separating them would let `("ab", "cd")`
            // collide with `("abc", "d")`. Our format prefixes each
            // field with its length, so these must differ.
            let a = compute_cache_key(b"", "ab", "cd", "ada", PipelineFeatureFlags::empty());
            let b = compute_cache_key(b"", "abc", "d", "ada", PipelineFeatureFlags::empty());
            assert_ne!(a, b);
        }

        #[test]
        fn cache_path_is_hex_and_bin_extension() {
            let d = Path::new("/tmp");
            let p = cache_path(d, &[0xAB_u8; 32]);
            let fname = p.file_name().unwrap().to_string_lossy().to_string();
            assert!(fname.ends_with(".bin"));
            assert!(fname.contains("abababab"));
            assert_eq!(fname.len(), 64 + 4); // 64 hex + ".bin"
        }

        #[test]
        fn load_miss_returns_none() {
            let dir = tempfile::tempdir().unwrap();
            let r = load(dir.path(), &key1()).unwrap();
            assert!(r.is_none());
        }

        #[test]
        fn store_then_load_roundtrips() {
            let dir = tempfile::tempdir().unwrap();
            let payload = b"spirv-bytes-or-similar".to_vec();
            store(dir.path(), &key1(), &payload).unwrap();
            let loaded = load(dir.path(), &key1()).unwrap();
            assert_eq!(loaded.as_deref(), Some(payload.as_slice()));
        }

        #[test]
        fn store_creates_missing_cache_dir() {
            let parent = tempfile::tempdir().unwrap();
            let nested = parent.path().join("a").join("b").join("c");
            assert!(!nested.exists());
            store(&nested, &key1(), b"blob").unwrap();
            let loaded = load(&nested, &key1()).unwrap();
            assert_eq!(loaded.as_deref(), Some(b"blob".as_slice()));
        }

        #[test]
        fn different_keys_do_not_overlap() {
            let dir = tempfile::tempdir().unwrap();
            store(dir.path(), &key1(), b"one").unwrap();
            store(dir.path(), &key2(), b"two").unwrap();
            assert_eq!(
                load(dir.path(), &key1()).unwrap().as_deref(),
                Some(b"one".as_slice())
            );
            assert_eq!(
                load(dir.path(), &key2()).unwrap().as_deref(),
                Some(b"two".as_slice())
            );
        }

        #[test]
        fn overwriting_same_key_preserves_atomicity() {
            let dir = tempfile::tempdir().unwrap();
            store(dir.path(), &key1(), b"first").unwrap();
            store(dir.path(), &key1(), b"second").unwrap();
            assert_eq!(
                load(dir.path(), &key1()).unwrap().as_deref(),
                Some(b"second".as_slice())
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::CompiledPipeline as _;
    use vyre_foundation::ir::{BufferDecl, DataType, Expr, Node};

    /// Minimal backend that records how many times `dispatch` was called.
    /// Used to verify the passthrough pipeline routes every dispatch back
    /// through the backend (no inadvertent caching at the framework layer).
    #[derive(Default)]
    struct CountingBackend {
        calls: std::sync::Mutex<usize>,
    }

    impl crate::backend::private::Sealed for CountingBackend {}

    impl VyreBackend for CountingBackend {
        fn id(&self) -> &'static str {
            "counting"
        }

        fn dispatch(
            &self,
            _program: &Program,
            inputs: &[Vec<u8>],
            _config: &DispatchConfig,
        ) -> Result<Vec<Vec<u8>>, BackendError> {
            *self.calls.lock().unwrap() += 1;
            // Echo: each output buffer mirrors the input at the same index.
            Ok(inputs.to_vec())
        }
    }

    fn empty_program() -> Program {
        // The framework treats Program opaquely for the passthrough path —
        // we never need to lower or execute. A minimal default value is
        // sufficient to exercise the trait surface.
        Program::default()
    }

    #[test]
    fn passthrough_routes_every_dispatch_to_backend() {
        let backend = Arc::new(CountingBackend::default());
        let pipeline = compile(
            backend.clone(),
            &empty_program(),
            &DispatchConfig::default(),
        )
        .unwrap();
        let inputs = vec![vec![1u8, 2, 3]];
        for _ in 0..10 {
            let out = pipeline
                .dispatch(&inputs, &DispatchConfig::default())
                .unwrap();
            assert_eq!(out, inputs);
        }
        assert_eq!(*backend.calls.lock().unwrap(), 10);
    }

    #[test]
    fn passthrough_id_includes_backend_id() {
        let backend = Arc::new(CountingBackend::default());
        let pipeline = compile(backend, &empty_program(), &DispatchConfig::default()).unwrap();
        assert!(pipeline.id().starts_with("counting:"));
    }

    #[test]
    fn passthrough_dispatch_borrowed_uses_backend_borrowed_override() {
        #[derive(Default)]
        struct BorrowRecordingBackend {
            owned_calls: std::sync::Mutex<usize>,
            borrowed_calls: std::sync::Mutex<usize>,
        }

        impl crate::backend::private::Sealed for BorrowRecordingBackend {}

        impl VyreBackend for BorrowRecordingBackend {
            fn id(&self) -> &'static str {
                "borrow-recording"
            }

            fn dispatch(
                &self,
                _program: &Program,
                inputs: &[Vec<u8>],
                _config: &DispatchConfig,
            ) -> Result<Vec<Vec<u8>>, BackendError> {
                *self.owned_calls.lock().unwrap() += 1;
                Ok(inputs.to_vec())
            }

            fn dispatch_borrowed(
                &self,
                _program: &Program,
                inputs: &[&[u8]],
                _config: &DispatchConfig,
            ) -> Result<Vec<Vec<u8>>, BackendError> {
                *self.borrowed_calls.lock().unwrap() += 1;
                Ok(inputs.iter().map(|input| (*input).to_vec()).collect())
            }
        }

        let backend = Arc::new(BorrowRecordingBackend::default());
        let pipeline = compile(
            backend.clone(),
            &empty_program(),
            &DispatchConfig::default(),
        )
        .unwrap();
        let input = [7u8, 8, 9];

        let out = pipeline
            .dispatch_borrowed(&[input.as_slice()], &DispatchConfig::default())
            .unwrap();

        assert_eq!(out, vec![input.to_vec()]);
        assert_eq!(*backend.borrowed_calls.lock().unwrap(), 1);
        assert_eq!(*backend.owned_calls.lock().unwrap(), 0);
    }

    #[test]
    fn per_call_config_overrides_compile_config() {
        // Backend that records the profile string it observed on dispatch.
        struct ProfileEcho {
            seen: std::sync::Mutex<Vec<Option<String>>>,
        }
        impl crate::backend::private::Sealed for ProfileEcho {}
        impl VyreBackend for ProfileEcho {
            fn id(&self) -> &'static str {
                "profile-echo"
            }
            fn dispatch(
                &self,
                _program: &Program,
                _inputs: &[Vec<u8>],
                config: &DispatchConfig,
            ) -> Result<Vec<Vec<u8>>, BackendError> {
                self.seen.lock().unwrap().push(config.profile.clone());
                Ok(vec![])
            }
        }
        let backend = Arc::new(ProfileEcho {
            seen: Default::default(),
        });
        let compile_cfg = DispatchConfig {
            profile: Some("compile-time".to_string()),
            ulp_budget: None,
            ..DispatchConfig::default()
        };
        let pipeline = compile(backend.clone(), &empty_program(), &compile_cfg).unwrap();

        // Default per-call config falls back to compile-time profile.
        pipeline.dispatch(&[], &DispatchConfig::default()).unwrap();
        // Non-default per-call config overrides.
        pipeline
            .dispatch(
                &[],
                &DispatchConfig {
                    profile: Some("per-call".to_string()),
                    ulp_budget: None,
                    ..DispatchConfig::default()
                },
            )
            .unwrap();

        let seen = backend.seen.lock().unwrap();
        assert_eq!(seen[0], Some("compile-time".to_string()));
        assert_eq!(seen[1], Some("per-call".to_string()));
    }

    #[test]
    fn native_pipeline_is_used_when_backend_provides_one() {
        // Backend that returns a NoopPipeline from compile_native; verifies
        // the framework hands it back directly instead of wrapping in
        // passthrough.
        struct NativePipeline;
        impl crate::backend::private::Sealed for NativePipeline {}
        impl CompiledPipeline for NativePipeline {
            fn id(&self) -> &str {
                "native-pipeline"
            }
            fn dispatch(
                &self,
                _: &[Vec<u8>],
                _: &DispatchConfig,
            ) -> Result<Vec<Vec<u8>>, BackendError> {
                Ok(vec![vec![42]])
            }
        }
        struct NativeBackend;
        impl crate::backend::private::Sealed for NativeBackend {}
        impl VyreBackend for NativeBackend {
            fn id(&self) -> &'static str {
                "native"
            }
            fn dispatch(
                &self,
                _: &Program,
                _: &[Vec<u8>],
                _: &DispatchConfig,
            ) -> Result<Vec<Vec<u8>>, BackendError> {
                Err(BackendError::new(
                    "native backend should be reached via compile, not dispatch. \
                     Fix: use vyre::pipeline::compile then call CompiledPipeline::dispatch.",
                ))
            }
            fn compile_native(
                &self,
                _: &Program,
                _: &DispatchConfig,
            ) -> Result<Option<Arc<dyn CompiledPipeline>>, BackendError> {
                Ok(Some(Arc::new(NativePipeline)))
            }
        }
        let backend = Arc::new(NativeBackend);
        let pipeline = compile(backend, &empty_program(), &DispatchConfig::default()).unwrap();
        assert_eq!(pipeline.id(), "native-pipeline");
        let outputs = pipeline.dispatch(&[], &DispatchConfig::default()).unwrap();
        assert_eq!(outputs, vec![vec![42]]);
    }

    #[test]
    #[allow(deprecated)]
    fn compile_rejects_non_region_programs() {
        let backend = Arc::new(CountingBackend::default());
        let program = Program::new(
            vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), Expr::u32(9)), Node::Return],
        );
        let error = match compile(backend, &program, &DispatchConfig::default()) {
            Ok(_) => panic!("Fix: runtime admission must reject raw top-level statements"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("top-level Region-wrapped Program"),
            "Fix: runtime admission rejection must mention the region invariant, got: {error}"
        );
    }
}
