//! P4.3 — content-addressed pipeline cache.
//!
//! Every compiled `Program` has a stable fingerprint =
//! `blake3(canonicalize(program).to_wire())`. The fingerprint
//! becomes the cache key: two authors who write the same
//! computation via different spellings share cached SPIR-V /
//! native-backend artifacts, skipping recompilation.
//!
//! The cache is deliberately simple in-memory at this layer —
//! consumers that want on-disk or crates.io-sourced blobs compose
//! `PipelineCache` with [`DiskCache`] or [`RemoteCache`] below.

#![allow(clippy::missing_const_for_thread_local, clippy::explicit_auto_deref)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use vyre_foundation::ir::Program;

// Reuse wire bytes across `PipelineFingerprint::of` calls to cut steady-state
// alloc churn (the canonical Program clone + sort is unchanged; wire buffer is the largest slab).
thread_local! {
    static FINGERPRINT_WIRE_SCRATCH: RefCell<Vec<u8>> = RefCell::new(Vec::new());
}

/// Program-intrinsic fields that are permitted to contribute to
/// [`PipelineFingerprint`].
///
/// The key is intentionally narrow:
/// - canonical IR node graph
/// - declared buffer layout (names, bindings, access, dtypes, counts)
/// - the `Program`'s declared workgroup size
/// - canonical wire-format framing emitted by `Program::to_wire()`
///
/// The key intentionally excludes every dispatch-time concern:
/// - input buffer count or byte contents
/// - `DispatchConfig` labels, profiles, timeout, and ULP budget
/// - runtime workgroup overrides or launch geometry
///
/// The compile-time assertion below pins `PipelineFingerprint::of` to
/// `fn(&Program) -> PipelineFingerprint`, so no per-dispatch structure can
/// accidentally enter the key without changing the public signature.
const PIPELINE_FINGERPRINT_ALLOWED_FIELDS: &[&str] = &[
    "canonical_ir_graph",
    "buffer_layout",
    "declared_workgroup_size",
    "canonical_wire_framing",
];

/// The blake3 fingerprint of a canonicalized Program. 32 bytes so
/// collisions are cryptographically impossible for our scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PipelineFingerprint(pub [u8; 32]);

const _: fn(&Program) -> PipelineFingerprint = PipelineFingerprint::of;

impl PipelineFingerprint {
    /// Derive a fingerprint from a Program. Runs
    /// `vyre_foundation::transform::optimize::canonicalize::run`
    /// first so semantically-equal Programs share a fingerprint.
    ///
    /// Only program-intrinsic state is allowed into this hash. The
    /// fingerprint must stay stable across different dispatch inputs and
    /// execution-time knobs so the cache remains content-addressed rather
    /// than dispatch-addressed.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre_foundation::ir::Program;
    /// use vyre_runtime::PipelineFingerprint;
    ///
    /// let a = Program::empty();
    /// let b = Program::empty();
    ///
    /// assert_eq!(PipelineFingerprint::of(&a), PipelineFingerprint::of(&b));
    /// ```
    #[must_use]
    pub fn of(program: &Program) -> Self {
        Self(hash_pipeline_fingerprint(program))
    }

    /// Hex-encode the fingerprint for human display + path-safe
    /// storage. Lowercase, no separators, 64 chars.
    #[must_use]
    pub fn hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for b in &self.0 {
            use std::fmt::Write;
            let _ = write!(&mut out, "{b:02x}");
        }
        out
    }
}

/// Trait for persistent pipeline-cache backends. [`DiskCache`] and
/// [`RemoteCache`] ship disk- and network-backed implementations;
/// tests here use the in-memory [`InMemoryPipelineCache`].
pub trait PipelineCacheStore: Send + Sync {
    /// Look up a cached artifact for this fingerprint.
    ///
    /// V7-PERF-009 (legacy): the default impl delegates to `get_arc`
    /// and clones the payload. Hot-path consumers should call
    /// `get_arc` directly to avoid the per-hit `Vec<u8>` allocation.
    fn get(&self, fp: &PipelineFingerprint) -> Option<Vec<u8>> {
        self.get_arc(fp).map(|arc| (*arc).clone())
    }

    /// V7-PERF-009: zero-clone hot-path lookup. Returns the cached
    /// artifact as an `Arc<Vec<u8>>` so multiple consumers share the
    /// underlying allocation. Default impl wraps `get` for backends
    /// that don't yet store payloads behind an `Arc`; in-memory and
    /// layered caches override to return their internal `Arc` directly.
    fn get_arc(&self, fp: &PipelineFingerprint) -> Option<Arc<Vec<u8>>> {
        self.get(fp).map(Arc::new)
    }

    /// Insert a pre-compiled artifact. Implementations may dedupe
    /// or evict per their own policy.
    fn put(&self, fp: PipelineFingerprint, artifact: Vec<u8>);
}

/// In-memory pipeline cache — zero-persistence, zero-network, sharded
/// `HashMap`s behind mutexes so concurrent `get`/`put` on different
/// fingerprints rarely contend (VYRE_RUNTIME / PERF hot-cache audit).
#[derive(Debug)]
pub struct InMemoryPipelineCache {
    shards: [Mutex<HashMap<PipelineFingerprint, Arc<Vec<u8>>>>; Self::SHARD_COUNT],
}

impl InMemoryPipelineCache {
    const SHARD_COUNT: usize = 16;

    #[inline]
    fn shard_index(fp: &PipelineFingerprint) -> usize {
        (fp.0[0] as usize) % Self::SHARD_COUNT
    }

    /// Construct an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current entry count. Thread-safe snapshot.
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len())
            .sum()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.shards
            .iter()
            .all(|s| s.lock().unwrap_or_else(|e| e.into_inner()).is_empty())
    }
}

impl Default for InMemoryPipelineCache {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
        }
    }
}

impl PipelineCacheStore for InMemoryPipelineCache {
    /// V7-PERF-009: zero-clone hot-path lookup. The cache already stores
    /// payloads behind `Arc<Vec<u8>>`, so a hit is one refcount bump.
    fn get_arc(&self, fp: &PipelineFingerprint) -> Option<Arc<Vec<u8>>> {
        let i = Self::shard_index(fp);
        self.shards[i]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(fp)
            .cloned()
    }

    fn put(&self, fp: PipelineFingerprint, artifact: Vec<u8>) {
        let i = Self::shard_index(&fp);
        self.shards[i]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(fp, Arc::new(artifact));
    }
}

/// Composite store that reads from every backend and writes to
/// the first. Lets callers compose `[RamStore, DiskStore, RemoteStore]`
/// so a miss at the fast layer falls through to slower layers.
pub struct LayeredPipelineCache {
    layers: Vec<Arc<dyn PipelineCacheStore>>,
}

impl LayeredPipelineCache {
    /// Construct from an ordered list (fastest-first). Lookups
    /// consult every layer in order; writes land in the first layer
    /// only — downstream layers are expected to be populated
    /// independently (e.g., from a pre-compiled blob bundle).
    #[must_use]
    pub fn new(layers: Vec<Arc<dyn PipelineCacheStore>>) -> Self {
        Self { layers }
    }
}

impl PipelineCacheStore for LayeredPipelineCache {
    /// V7-PERF-009: forward through to each layer's zero-clone path so
    /// the hit propagates without an intermediate `Vec<u8>` allocation.
    fn get_arc(&self, fp: &PipelineFingerprint) -> Option<Arc<Vec<u8>>> {
        for layer in &self.layers {
            if let Some(arc) = layer.get_arc(fp) {
                return Some(arc);
            }
        }
        None
    }

    fn put(&self, fp: PipelineFingerprint, artifact: Vec<u8>) {
        if let Some(first) = self.layers.first() {
            first.put(fp, artifact);
        }
    }
}

/// Disk-backed pipeline cache. Writes one file per fingerprint
/// under `<root>/<hex>.bin`. Reads are stateless; writes are
/// `write + rename` for atomicity. No eviction policy today
/// (user decides) — the footprint is bounded by
/// sum(artifact_size × unique_canonical_programs).
#[derive(Debug)]
pub struct DiskCache {
    root: PathBuf,
    // Serialize concurrent put()s so two threads that happen to
    // compile the same program at the same time don't race on
    // rename(). Thread-safe; concurrent get() remains lock-free.
    write_lock: Mutex<()>,
}

impl DiskCache {
    /// Construct a cache rooted at `root`. Creates the directory if
    /// it doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns [`DiskCacheError::Io`] when the directory can't be
    /// created.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, DiskCacheError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(DiskCacheError::Io)?;
        Ok(Self {
            root,
            write_lock: Mutex::new(()),
        })
    }

    /// Construct a cache rooted at `~/.cache/vyre/pipelines/` (or
    /// `$XDG_CACHE_HOME/vyre/pipelines/` if set).
    ///
    /// # Errors
    ///
    /// Returns [`DiskCacheError::CacheDirUnknown`] when neither env
    /// var resolves, or [`DiskCacheError::Io`] on mkdir failure.
    pub fn in_user_cache() -> Result<Self, DiskCacheError> {
        let base = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".cache")))
            .ok_or(DiskCacheError::CacheDirUnknown)?;
        Self::new(base.join("vyre").join("pipelines"))
    }

    /// Root directory this cache operates on.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for(&self, fp: &PipelineFingerprint) -> PathBuf {
        self.root.join(format!("{}.bin", fp.hex()))
    }
}

// On-disk layout:
//   <payload bytes..>  <32-byte blake3 footer>
// Total file size = payload.len() + 32. Get verifies the footer
// before returning the payload; mismatches or truncated files
// return None so the caller recompiles. Covers torn writes +
// bit-rot + deliberate tampering.
const CHECKSUM_LEN: usize = 32;

fn hash_pipeline_fingerprint(program: &Program) -> [u8; 32] {
    debug_assert_eq!(
        PIPELINE_FINGERPRINT_ALLOWED_FIELDS.len(),
        4,
        "Fix: update PIPELINE_FINGERPRINT_ALLOWED_FIELDS whenever the fingerprint contract changes."
    );
    let canonical = vyre_foundation::transform::optimize::canonicalize::run(program.clone());
    // CRITIQUE_RUNTIME_2026-04-23 Finding 1: `structural_eq` treats
    // buffer declaration order as irrelevant (via
    // `buffers_equal_ignoring_declaration_order`), but `to_wire()`
    // serialises buffers in declaration order. Two semantically
    // equivalent programs whose buffer decls happen to be in a
    // different order would therefore hash to different fingerprints,
    // fragmenting the content-addressed cache.
    //
    // Sort buffers by (binding, name) before serialising so the wire
    // form is invariant under declaration reordering. This is the
    // only place the fingerprint is computed, so the rest of the
    // Program API keeps its author-preferred declaration order.
    let mut sorted_buffers = canonical.buffers().to_vec();
    sorted_buffers.sort_by(|a, b| {
        a.binding()
            .cmp(&b.binding())
            .then_with(|| a.name().cmp(b.name()))
    });
    let workgroup = canonical.workgroup_size();
    let entry = canonical.entry().to_vec();
    let normalised = Program::wrapped(sorted_buffers, workgroup, entry);
    FINGERPRINT_WIRE_SCRATCH.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        normalised
            .to_wire_into(&mut *buf)
            .expect("Fix: canonical Program must always serialize");
        *::blake3::hash(&*buf).as_bytes()
    })
}

impl PipelineCacheStore for DiskCache {
    fn get(&self, fp: &PipelineFingerprint) -> Option<Vec<u8>> {
        let path = self.path_for(fp);
        // FINDING-CACHE-1: reject symlinks before reading. `symlink_metadata`
        // does NOT follow the symlink; regular-file check is strict.
        let meta = fs::symlink_metadata(&path).ok()?;
        if !meta.file_type().is_file() {
            return None;
        }
        let bytes = fs::read(&path).ok()?;
        // FINDING-CACHE-2: verify the checksum footer. A torn write
        // that left fewer than 32 bytes, or any bit flip in payload,
        // fails this gate.
        if bytes.len() < CHECKSUM_LEN {
            return None;
        }
        let (payload, footer) = bytes.split_at(bytes.len() - CHECKSUM_LEN);
        let expected = ::blake3::hash(payload);
        if footer != expected.as_bytes() {
            return None;
        }
        Some(payload.to_vec())
    }

    fn put(&self, fp: PipelineFingerprint, artifact: Vec<u8>) {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let final_path = self.path_for(&fp);
        let tmp_path = self.root.join(format!(".{}.bin.tmp", fp.hex()));

        // FINDING-CACHE-2: write payload + blake3 footer in one shot,
        // then fsync to flush to the platter so a crash before rename
        // leaves either the prior file or the temp file (never a
        // half-written final).
        let write_fsync_rename = || -> io::Result<()> {
            let checksum = ::blake3::hash(&artifact);
            let mut f = File::create(&tmp_path)?;
            f.write_all(&artifact)?;
            f.write_all(checksum.as_bytes())?;
            f.sync_all()?;
            drop(f);
            // FINDING-CACHE-1: if the final path is a symlink, unlink it
            // first so rename replaces the symlink (not its target).
            if let Ok(meta) = fs::symlink_metadata(&final_path) {
                if meta.file_type().is_symlink() {
                    let _ = fs::remove_file(&final_path);
                }
            }
            fs::rename(&tmp_path, &final_path)?;
            Ok(())
        };
        if write_fsync_rename().is_err() {
            // Best-effort; caller falls back to recompile. Clean up
            // the tmp file so it doesn't accumulate on failure.
            let _ = fs::remove_file(&tmp_path);
        }
    }
}

/// Errors from disk-backed pipeline cache construction / use.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiskCacheError {
    /// Neither `$XDG_CACHE_HOME` nor `$HOME` is set.
    #[error(
        "could not resolve a user cache directory — set XDG_CACHE_HOME or HOME, or call DiskCache::new() with an explicit path"
    )]
    CacheDirUnknown,
    /// `std::io` failure (mkdir, read, write).
    #[error("disk-cache I/O error: {0}")]
    Io(#[from] io::Error),
}

/// HTTPS-backed cache that reads pre-compiled artifacts from a
/// base URL. Feature-gated on `remote` so library users who only
/// want disk caching don't pull in `ureq`.
///
/// Writes are **no-ops** — `RemoteCache` is a read-through layer.
/// Publishing to a remote registry is a separate `vyre publish-cache`
/// xtask, not part of this runtime.
#[cfg(feature = "remote")]
pub struct RemoteCache {
    base_url: String,
}

#[cfg(feature = "remote")]
impl RemoteCache {
    /// Construct from a base URL. The cache fetches
    /// `<base_url>/<fp_hex>.bin` for each lookup.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }
}

#[cfg(feature = "remote")]
impl PipelineCacheStore for RemoteCache {
    fn get(&self, fp: &PipelineFingerprint) -> Option<Vec<u8>> {
        let url = format!("{}/{}.bin", self.base_url.trim_end_matches('/'), fp.hex());
        let resp = ureq::get(&url).call().ok()?;
        let mut buf = Vec::new();
        resp.into_reader().read_to_end(&mut buf).ok()?;
        Some(buf)
    }

    fn put(&self, _fp: PipelineFingerprint, _artifact: Vec<u8>) {
        // Remote cache is read-through; publishing is a separate flow.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_foundation::ir::{BufferDecl, DataType, Expr, Node, Program};

    fn tiny_program() -> Program {
        Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), Expr::u32(42))],
        )
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let a = PipelineFingerprint::of(&tiny_program());
        let b = PipelineFingerprint::of(&tiny_program());
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_hex_is_64_chars() {
        let fp = PipelineFingerprint::of(&tiny_program());
        assert_eq!(fp.hex().len(), 64);
    }

    #[test]
    fn canonically_equal_programs_share_fingerprint() {
        // `a + 1` and `1 + a` canonicalize to the same IR → same fingerprint.
        let p1 = Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::store(
                "out",
                Expr::u32(0),
                Expr::add(Expr::var("a"), Expr::u32(1)),
            )],
        );
        let p2 = Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::store(
                "out",
                Expr::u32(0),
                Expr::add(Expr::u32(1), Expr::var("a")),
            )],
        );
        let fp1 = PipelineFingerprint::of(&p1);
        let fp2 = PipelineFingerprint::of(&p2);
        assert_eq!(
            fp1, fp2,
            "canonicalize makes `a+1` and `1+a` share a fingerprint"
        );
    }

    #[test]
    fn fingerprint_changes_when_declared_program_shape_changes() {
        let base = tiny_program();
        let widened = Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32).with_count(1)],
            [64, 1, 1],
            vec![Node::store("out", Expr::u32(0), Expr::u32(42))],
        );

        assert_ne!(
            PipelineFingerprint::of(&base),
            PipelineFingerprint::of(&widened),
            "declared workgroup size is program-intrinsic and must change the fingerprint"
        );
    }

    #[test]
    fn in_memory_cache_roundtrip() {
        let cache = InMemoryPipelineCache::new();
        let fp = PipelineFingerprint::of(&tiny_program());
        assert!(cache.get(&fp).is_none());
        cache.put(fp, b"spirv-bytes".to_vec());
        assert_eq!(cache.get(&fp).unwrap(), b"spirv-bytes".to_vec());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn layered_cache_prefers_first_hit() {
        let fast = Arc::new(InMemoryPipelineCache::new());
        let slow = Arc::new(InMemoryPipelineCache::new());
        let fp = PipelineFingerprint::of(&tiny_program());
        slow.put(fp, b"fallback".to_vec());
        let cache = LayeredPipelineCache::new(vec![fast.clone(), slow]);
        // Miss in fast, hit in slow.
        assert_eq!(cache.get(&fp).unwrap(), b"fallback".to_vec());
        // Put lands in fast only.
        cache.put(fp, b"warmed".to_vec());
        assert_eq!(fast.get(&fp).unwrap(), b"warmed".to_vec());
    }
}
