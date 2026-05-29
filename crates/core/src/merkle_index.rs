//! Incremental scan support via a persisted file-content index.
//!
//! ## What it does
//!
//! On a fresh scan we compute, for every input chunk, a metadata tuple
//! `(mtime_ns, size, BLAKE3(content))` and store it under the file's
//! canonical path. On the next run, files whose `(mtime, size)` match
//! the stored values can be skipped *without re-reading the bytes* -
//! they almost certainly haven't changed (rsync-style trust). When
//! `(mtime, size)` differ but BLAKE3 matches we record the new mtime
//! and still skip - same content, different stat (touched, copied).
//!
//! Tier-B moat innovation #3 from audits/legendary-2026-04-26: "10–100×
//! speedup on CI re-runs" by skipping the 99% of files that didn't change.
//!
//! ## Schema versions
//!
//! - **v1 (legacy)** - `path → BLAKE3 hex` only. Loadable but lacks the
//!   metadata short-circuit; treated as cold-start to avoid mixing schemas.
//! - **v2 (current)** - `path → (mtime_ns, size, BLAKE3 hex)` plus a
//!   top-level `spec_hash` derived from the loaded detector set. A
//!   spec-hash mismatch invalidates the entire cache; this is the
//!   correctness fix for "added a detector but unchanged files were
//!   silently skipped, missing the new detection forever."
//!
//! ## Serialization
//!
//! JSON, on purpose. The dataset is one row per scanned file (≤ ~1M for
//! any sane repo) and JSON keeps the on-disk format trivial to debug,
//! diff, and version-control if a team wants to.
//!
//! ## Threat model
//!
//! Cached entries do NOT contain credentials. Storing a `(mtime, size,
//! content_hash)` tuple per scanned path leaks that the path *exists*
//! and what its content fingerprint is, which is why `--lockdown`
//! refuses to load or write the cache at all.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::merkle_spec_hash::{hex_encode, hex_to_array};

pub use crate::merkle_spec_hash::compute_spec_hash;

/// On-disk per-entry record (v2). The `mtime_ns` + `size` pair is the
/// fast-path key: a successful match short-circuits the BLAKE3 read
/// entirely. `hash` remains as a paranoid-mode verifier and as the
/// authoritative content fingerprint when mtime alone changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EntryV2 {
    /// `mtime` in nanoseconds since UNIX epoch. Stored as `u64` so we
    /// don't lose ext4/NTFS sub-second precision; older filesystems
    /// (FAT32 with 2-second resolution) just round-trip the rounded value.
    mtime_ns: u64,
    /// File size in bytes from `fs::metadata`.
    size: u64,
    /// BLAKE3 hex digest of the chunk content.
    hash: String,
}

/// Top-level on-disk schema.
#[derive(Debug, Serialize, Deserialize)]
struct OnDisk {
    /// Schema version. Bumped on incompatible changes.
    version: u32,
    /// Hex BLAKE3 of the canonical detector-spec digest. Optional for
    /// schemas written before spec hashing was added; loaders treating
    /// `None` as "trust the cache" stay back-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spec_hash: Option<String>,
    /// `path → entry`. Stored as hex strings (not raw bytes) so a human
    /// can `git diff` the file and see which entries changed.
    entries: HashMap<String, EntryV2>,
}

const SCHEMA_VERSION: u32 = 2;

/// Shard count: spreads concurrent `record` / `unchanged` calls across
/// independent locks so tiny-file storms don't serialize all rayon workers.
const MERKLE_SHARDS: usize = 64;

fn shard_index(path: &Path) -> usize {
    let mut h = DefaultHasher::new();
    path.hash(&mut h);
    (h.finish() as usize) % MERKLE_SHARDS
}

/// In-memory per-entry record. Mirrors [`EntryV2`] but holds the hash as
/// a fixed-size array - saves the per-lookup hex-decode cost on the
/// `unchanged` hot path.
#[derive(Debug, Clone, Copy)]
struct CacheEntry {
    mtime_ns: u64,
    size: u64,
    hash: [u8; 32],
}

/// In-memory file-hash index loaded from / saved to a JSON cache file.
///
/// Concurrency model: the orchestrator holds an `Arc<MerkleIndex>` and
/// records new entries as chunks arrive from rayon-parallel sources.
/// Paths are sharded across [`MERKLE_SHARDS`] mutex-protected maps so
/// concurrent updates rarely contend.
#[derive(Debug)]
pub struct MerkleIndex {
    shards: Vec<Mutex<HashMap<PathBuf, CacheEntry>>>,
}

impl MerkleIndex {
    /// Construct a fresh, empty [`MerkleIndex`] with no cached entries.
    pub fn empty() -> Self {
        Self {
            shards: (0..MERKLE_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
        }
    }

    /// Load the index from `path` without spec-hash gating. Returns an
    /// empty index when the file doesn't exist (first run) or fails to
    /// parse (treat as cold start - safer than poisoning the cache from
    /// a corrupted artifact). v1 caches are intentionally rejected as
    /// cold-start because they lack metadata fields.
    pub fn load(path: &Path) -> Self {
        sweep_stale_tmp_files(path);
        Self::load_with_spec_inner(path, None)
    }

    /// Load the index, gated on a matching detector-spec hash. When the
    /// stored `spec_hash` differs from `expected_spec_hash`, the cache is
    /// treated as cold-start. This is the correctness gate that prevents
    /// "added a detector → unchanged file silently skipped → new
    /// detector never runs against it" from ever happening.
    pub fn load_with_spec(path: &Path, expected_spec_hash: &[u8; 32]) -> Self {
        sweep_stale_tmp_files(path);
        Self::load_with_spec_inner(path, Some(expected_spec_hash))
    }

    fn load_with_spec_inner(path: &Path, expected_spec_hash: Option<&[u8; 32]>) -> Self {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::empty(),
            Err(e) => {
                tracing::warn!(
                    cache = %path.display(),
                    error = %e,
                    "merkle index file read failed; treating as cold start"
                );
                return Self::empty();
            }
        };
        let on_disk: OnDisk = match serde_json::from_slice(&bytes) {
            Ok(d) => d,
            Err(error) => {
                tracing::warn!(
                    cache = %path.display(),
                    %error,
                    "merkle index parse failed; treating as cold start"
                );
                return Self::empty();
            }
        };
        if on_disk.version != SCHEMA_VERSION {
            tracing::warn!(
                cache = %path.display(),
                version = on_disk.version,
                expected = SCHEMA_VERSION,
                "merkle index schema mismatch; treating as cold start"
            );
            return Self::empty();
        }
        if let Some(expected) = expected_spec_hash {
            let stored_match = on_disk
                .spec_hash
                .as_deref()
                .and_then(hex_to_array)
                .is_some_and(|stored| &stored == expected);
            if !stored_match {
                tracing::info!(
                    cache = %path.display(),
                    "detector spec changed since last scan; cache invalidated"
                );
                return Self::empty();
            }
        }
        let entries: HashMap<PathBuf, CacheEntry> = on_disk
            .entries
            .into_iter()
            .filter_map(|(p, e)| {
                hex_to_array(&e.hash).map(|hash| {
                    (
                        PathBuf::from(p),
                        CacheEntry {
                            mtime_ns: e.mtime_ns,
                            size: e.size,
                            hash,
                        },
                    )
                })
            })
            .collect();
        tracing::info!(
            cache = %path.display(),
            count = entries.len(),
            "merkle index loaded"
        );
        let idx = Self::empty();
        for (p, e) in entries {
            let i = shard_index(&p);
            idx.shards[i].lock().insert(p, e);
        }
        idx
    }

    /// Persist the index without binding it to a detector-spec hash. Old
    /// callers stay on this path; the next-cycle load won't enforce a
    /// spec match. Use [`Self::save_with_spec`] for the safe modern path.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        self.save_inner(path, None)
    }

    /// Persist the index *with* the given detector-spec hash so a future
    /// load can detect detector drift and invalidate cleanly.
    pub fn save_with_spec(&self, path: &Path, spec_hash: &[u8; 32]) -> std::io::Result<()> {
        self.save_inner(path, Some(spec_hash))
    }

    fn save_inner(&self, path: &Path, spec_hash: Option<&[u8; 32]>) -> std::io::Result<()> {
        // Concurrency note: two `keyhog scan --incremental` processes
        // running against overlapping paths will both want to write
        // `merkle.idx`. The tmp-file uses `std::process::id()` so
        // there's no tmp-name collision, but the final `rename` is
        // last-writer-wins.
        //
        // To minimise data loss on concurrent saves, READ the
        // current on-disk entries first and merge our in-memory
        // state on top - entries in memory take precedence (we just
        // observed those files in this scan), but disk entries that
        // we DIDN'T touch are preserved. This narrows the data-loss
        // window from "entire scan" to "between read-and-rename"
        // (~milliseconds) instead of "between scan-start and save".
        //
        // A truly race-free solution needs an OS-level file lock
        // (`fcntl(F_SETLK)` / `LockFileEx`); that would block the
        // second writer entirely. We accept the small remaining
        // race as a correctness/perf trade - losing a few entries
        // means an extra rescan, not a missed leak.
        let mut merged = HashMap::<PathBuf, CacheEntry>::new();
        // Read existing on-disk entries first. Use the SAME spec
        // hash we're about to write - if disk was written under a
        // different spec, those entries are stale (a future load
        // would invalidate them) and we drop them now. If spec
        // matches (or this is the no-spec save path), preserve.
        // Format-mismatch / corrupted-file paths already log inside
        // `load`; ignore the error here so a bad on-disk state
        // doesn't stop us writing a fresh one.
        let on_disk_now = match spec_hash {
            Some(hash) => Self::load_with_spec(path, hash),
            None => Self::load(path),
        };
        for shard in &on_disk_now.shards {
            merged.extend(shard.lock().iter().map(|(p, e)| (p.clone(), *e)));
        }
        // In-memory entries layer on top - last-write-wins by path.
        for shard in &self.shards {
            merged.extend(shard.lock().iter().map(|(p, e)| (p.clone(), *e)));
        }
        let entries: HashMap<String, EntryV2> = merged
            .iter()
            .map(|(p, e)| {
                (
                    p.display().to_string(),
                    EntryV2 {
                        mtime_ns: e.mtime_ns,
                        size: e.size,
                        hash: hex_encode(&e.hash),
                    },
                )
            })
            .collect();
        let on_disk = OnDisk {
            version: SCHEMA_VERSION,
            spec_hash: spec_hash.map(hex_encode),
            entries,
        };
        let serialized = serde_json::to_vec_pretty(&on_disk)
            .map_err(|e| std::io::Error::other(format!("merkle index encode: {e}")))?;
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(parent)?;
        // `NamedTempFile::new_in` creates a randomly-named file in
        // the same directory as the final target, then `persist`
        // atomic-renames it. If we panic between create and persist,
        // NamedTempFile's Drop deletes the tmp file - earlier code
        // used `path.with_extension(format!("tmp.{pid}"))` and
        // leaked the tmp on panic. A SIGTERM/SIGKILL still leaks
        // (Drop doesn't run); the only complete fix for that is a
        // startup-time stale-tmp sweep, which we accept as a
        // smaller residual hygiene issue.
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        std::io::Write::write_all(&mut tmp, &serialized)?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| e.error)?;
        Ok(())
    }

    /// Hash the given content with BLAKE3 (32-byte output).
    pub fn hash_content(content: &[u8]) -> [u8; 32] {
        *blake3::hash(content).as_bytes()
    }

    /// Returns `true` when `path` was previously indexed with the SAME
    /// content hash. Kept for callers that already have the hash in hand
    /// (e.g. the orchestrator's chunk-level skip path).
    pub fn unchanged(&self, path: &Path, content_hash: &[u8; 32]) -> bool {
        let i = shard_index(path);
        self.shards[i]
            .lock()
            .get(path)
            .is_some_and(|prev| &prev.hash == content_hash)
    }

    /// Returns `true` when `(path, mtime_ns, size)` exactly matches a
    /// stored entry. This is the **fast-path skip** - it avoids reading
    /// the file at all, which is the dominant cost on cold-cache disk.
    /// A `false` return means "either we've never seen this path, or
    /// metadata differs - caller must read + hash to decide."
    pub fn metadata_unchanged(&self, path: &Path, mtime_ns: u64, size: u64) -> bool {
        let i = shard_index(path);
        self.shards[i]
            .lock()
            .get(path)
            .is_some_and(|prev| prev.mtime_ns == mtime_ns && prev.size == size)
    }

    /// Returns the stored `(mtime_ns, size, content_hash)` for `path`,
    /// or `None` if the index hasn't seen it. Used by paranoid-mode
    /// verifiers that want to confirm content didn't change even when
    /// metadata happens to match.
    pub fn lookup(&self, path: &Path) -> Option<(u64, u64, [u8; 32])> {
        let i = shard_index(path);
        self.shards[i]
            .lock()
            .get(path)
            .map(|e| (e.mtime_ns, e.size, e.hash))
    }

    /// Record a file's content hash. Back-compat shim that drops to a
    /// zero-metadata entry - calls into [`Self::record_with_metadata`]
    /// with `mtime_ns = 0` and `size = 0` so existing callers keep
    /// working but won't benefit from the metadata fast-path.
    pub fn record(&self, path: PathBuf, content_hash: [u8; 32]) {
        self.record_with_metadata(path, 0, 0, content_hash);
    }

    /// Record a file's metadata + content hash. Overwrites any prior
    /// entry at the same path. The path-shard mutex is held for the
    /// duration of the insert only; concurrent recordings against
    /// different shards never contend.
    pub fn record_with_metadata(
        &self,
        path: PathBuf,
        mtime_ns: u64,
        size: u64,
        content_hash: [u8; 32],
    ) {
        let i = shard_index(&path);
        self.shards[i].lock().insert(
            path,
            CacheEntry {
                mtime_ns,
                size,
                hash: content_hash,
            },
        );
    }

    /// Remove `path` from the index so the next scan treats it as new and
    /// re-reads + re-scans it.
    ///
    /// This is how incremental mode keeps its core safety guarantee: a file
    /// that produced ANY finding is never cached, so a secret in an otherwise
    /// unchanged file still surfaces on every later run instead of being
    /// silently skipped (the failure this module's own header warns about).
    /// Clean files - the 99% - stay cached, so the 10-100x speedup is
    /// unaffected, and because we store the ABSENCE of an entry rather than the
    /// finding, no secret value ever touches the on-disk index.
    pub fn forget(&self, path: &Path) {
        let i = shard_index(path);
        self.shards[i].lock().remove(path);
    }

    /// Number of indexed entries.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }

    /// Returns true if no cached entries are present across any shard.
    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|s| s.lock().is_empty())
    }
}

impl Default for MerkleIndex {
    fn default() -> Self {
        Self::empty()
    }
}

/// Default index location: `$XDG_CACHE_HOME/keyhog/merkle.idx` or
/// `~/.cache/keyhog/merkle.idx` on Linux, `~/Library/Caches/keyhog/...`
/// on macOS.
pub fn default_cache_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("keyhog").join("merkle.idx"))
}

/// Stale-tmp-file age cutoff. `tempfile::NamedTempFile`'s Drop impl
/// cleans up on panic but NOT on SIGKILL/SIGTERM - those leak a
/// random-named tmp file in the cache directory. Older than this
/// cutoff means "no chance an in-flight save by another keyhog
/// process is still using it." 1 hour is generous; the longest
/// merkle save in observed runs is < 1 second on a fully-loaded
/// 100k-file scan.
const STALE_TMP_CUTOFF_SECS: u64 = 60 * 60;

/// Best-effort sweep of stale tmp files left behind by SIGKILL'd
/// keyhog processes. Called from `load`/`load_with_spec` before
/// reading the cache so stale tmps don't accumulate forever next
/// to the real `merkle.idx`. Logged at debug level only since
/// failure is non-fatal.
fn sweep_stale_tmp_files(cache_path: &Path) {
    let Some(parent) = cache_path.parent() else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    let stem = cache_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("merkle");
    let now = std::time::SystemTime::now();
    let mut swept = 0usize;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        // tempfile::NamedTempFile uses random hex-suffixed names with
        // a `.tmp` prefix - match conservatively to avoid eating
        // unrelated files: `<stem>.tmp*` OR `.tmp<hex>`.
        let is_tmp_sibling =
            name_str.starts_with(&format!("{stem}.tmp")) || name_str.starts_with(".tmp");
        if !is_tmp_sibling {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = path.metadata() else { continue };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let age = match now.duration_since(modified) {
            Ok(d) => d,
            Err(_) => continue, // mtime in the future - skip rather than guess
        };
        if age.as_secs() < STALE_TMP_CUTOFF_SECS {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            swept += 1;
        }
    }
    if swept > 0 {
        tracing::debug!(
            count = swept,
            dir = %parent.display(),
            "swept stale cache tmp files left by an interrupted save"
        );
    }
}
