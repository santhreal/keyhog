//! Incremental scan support via a persisted file-content index.
//!
//! ## What it does
//!
//! On a fresh scan we compute, for every input chunk, a metadata tuple
//! `(mtime_ns, size, BLAKE3(content))` and store it under the file's
//! canonical path. On the next run, files whose `(mtime, size)` match
//! the stored values can be skipped *without re-reading the bytes* —
//! they almost certainly haven't changed (rsync-style trust). When
//! `(mtime, size)` differ but BLAKE3 matches we record the new mtime
//! and still skip — same content, different stat (touched, copied).
//!
//! Tier-B moat innovation #3 from audits/legendary-2026-04-26: "10–100×
//! speedup on CI re-runs" by skipping the 99% of files that didn't change.
//!
//! ## Schema versions
//!
//! - **v1 (legacy)** — `path → BLAKE3 hex` only. Loadable but lacks the
//!   metadata short-circuit; treated as cold-start to avoid mixing schemas.
//! - **v2 (current)** — `path → (mtime_ns, size, BLAKE3 hex)` plus a
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

use crate::spec::DetectorSpec;

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
/// a fixed-size array — saves the per-lookup hex-decode cost on the
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
    pub fn empty() -> Self {
        Self {
            shards: (0..MERKLE_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
        }
    }

    /// Load the index from `path` without spec-hash gating. Returns an
    /// empty index when the file doesn't exist (first run) or fails to
    /// parse (treat as cold start — safer than poisoning the cache from
    /// a corrupted artifact). v1 caches are intentionally rejected as
    /// cold-start because they lack metadata fields.
    pub fn load(path: &Path) -> Self {
        Self::load_with_spec_inner(path, None)
    }

    /// Load the index, gated on a matching detector-spec hash. When the
    /// stored `spec_hash` differs from `expected_spec_hash`, the cache is
    /// treated as cold-start. This is the correctness gate that prevents
    /// "added a detector → unchanged file silently skipped → new
    /// detector never runs against it" from ever happening.
    pub fn load_with_spec(path: &Path, expected_spec_hash: &[u8; 32]) -> Self {
        Self::load_with_spec_inner(path, Some(expected_spec_hash))
    }

    fn load_with_spec_inner(path: &Path, expected_spec_hash: Option<&[u8; 32]>) -> Self {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return Self::empty(),
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
    pub fn save_with_spec(
        &self,
        path: &Path,
        spec_hash: &[u8; 32],
    ) -> std::io::Result<()> {
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
        // state on top — entries in memory take precedence (we just
        // observed those files in this scan), but disk entries that
        // we DIDN'T touch are preserved. This narrows the data-loss
        // window from "entire scan" to "between read-and-rename"
        // (~milliseconds) instead of "between scan-start and save".
        //
        // A truly race-free solution needs an OS-level file lock
        // (`fcntl(F_SETLK)` / `LockFileEx`); that would block the
        // second writer entirely. We accept the small remaining
        // race as a correctness/perf trade — losing a few entries
        // means an extra rescan, not a missed leak.
        let mut merged = HashMap::<PathBuf, CacheEntry>::new();
        // Read existing on-disk entries first. Use the SAME spec
        // hash we're about to write — if disk was written under a
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
        // In-memory entries layer on top — last-write-wins by path.
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
        // NamedTempFile's Drop deletes the tmp file — earlier code
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
    /// stored entry. This is the **fast-path skip** — it avoids reading
    /// the file at all, which is the dominant cost on cold-cache disk.
    /// A `false` return means "either we've never seen this path, or
    /// metadata differs — caller must read + hash to decide."
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
    /// zero-metadata entry — calls into [`Self::record_with_metadata`]
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

    /// Number of indexed entries.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }

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

/// Compute a stable BLAKE3 digest over the canonical detector set so a
/// later scan can detect that detectors changed. Hashes a sorted list of
/// `id|regex|companion` strings — order-independent, comment-independent,
/// resilient to TOML key reordering.
pub fn compute_spec_hash(detectors: &[DetectorSpec]) -> [u8; 32] {
    let mut keys: Vec<String> = detectors
        .iter()
        .flat_map(|d| {
            let mut entries = Vec::with_capacity(1 + d.patterns.len() + d.companions.len());
            entries.push(format!("id:{}", d.id));
            for p in &d.patterns {
                entries.push(format!(
                    "p:{}|g:{}",
                    p.regex,
                    p.group.map(|g| g.to_string()).unwrap_or_default()
                ));
            }
            for c in &d.companions {
                entries.push(format!("c:{}|{}|w:{}|r:{}", c.name, c.regex, c.within_lines, c.required));
            }
            entries
        })
        .collect();
    keys.sort();
    let mut hasher = blake3::Hasher::new();
    for k in keys {
        hasher.update(k.as_bytes());
        hasher.update(b"\n");
    }
    *hasher.finalize().as_bytes()
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn hex_to_array(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hash(s: &[u8]) -> [u8; 32] {
        MerkleIndex::hash_content(s)
    }

    #[test]
    fn record_and_unchanged_roundtrip() {
        let idx = MerkleIndex::empty();
        let p = PathBuf::from("/tmp/example.env");
        let h = sample_hash(b"DB_PASS=secret123");
        idx.record(p.clone(), h);
        assert!(idx.unchanged(&p, &h));

        let h2 = sample_hash(b"DB_PASS=changed");
        assert!(!idx.unchanged(&p, &h2));
    }

    #[test]
    fn metadata_unchanged_matches_only_on_exact_pair() {
        let idx = MerkleIndex::empty();
        let p = PathBuf::from("/tmp/file");
        idx.record_with_metadata(p.clone(), 1_700_000_000_000_000_000, 4096, sample_hash(b"x"));
        assert!(idx.metadata_unchanged(&p, 1_700_000_000_000_000_000, 4096));
        // mtime drift
        assert!(!idx.metadata_unchanged(&p, 1_700_000_000_000_000_001, 4096));
        // size drift
        assert!(!idx.metadata_unchanged(&p, 1_700_000_000_000_000_000, 4097));
        // unknown path
        assert!(!idx.metadata_unchanged(Path::new("/never/seen"), 0, 0));
    }

    #[test]
    fn lookup_returns_full_tuple() {
        let idx = MerkleIndex::empty();
        let p = PathBuf::from("/tmp/file");
        let h = sample_hash(b"abc");
        idx.record_with_metadata(p.clone(), 42, 99, h);
        assert_eq!(idx.lookup(&p), Some((42, 99, h)));
        assert_eq!(idx.lookup(Path::new("/missing")), None);
    }

    #[test]
    fn unknown_path_is_changed() {
        let idx = MerkleIndex::empty();
        let h = sample_hash(b"x");
        assert!(!idx.unchanged(Path::new("/never/seen"), &h));
    }

    #[test]
    fn save_and_load_preserves_entries() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");

        let idx = MerkleIndex::empty();
        let p = PathBuf::from("/tmp/secrets.env");
        let h = sample_hash(b"hello world");
        idx.record_with_metadata(p.clone(), 12345, 11, h);
        idx.save(&cache_path).expect("save");

        let loaded = MerkleIndex::load(&cache_path);
        assert_eq!(loaded.len(), 1);
        assert!(loaded.unchanged(&p, &h));
        assert!(loaded.metadata_unchanged(&p, 12345, 11));
    }

    #[test]
    fn corrupted_cache_treated_as_cold_start() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");
        std::fs::write(&cache_path, b"this is not json").unwrap();
        let loaded = MerkleIndex::load(&cache_path);
        assert!(loaded.is_empty());
    }

    #[test]
    fn missing_cache_returns_empty() {
        let loaded = MerkleIndex::load(Path::new("/definitely/does/not/exist.idx"));
        assert!(loaded.is_empty());
    }

    #[test]
    fn schema_version_mismatch_treated_as_cold_start() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");
        let bad = serde_json::json!({
            "version": 99,
            "entries": { "/foo": { "mtime_ns": 0, "size": 0, "hash": "00".repeat(32) } }
        });
        std::fs::write(&cache_path, serde_json::to_vec(&bad).unwrap()).unwrap();
        let loaded = MerkleIndex::load(&cache_path);
        assert!(loaded.is_empty());
    }

    #[test]
    fn v1_legacy_format_treated_as_cold_start() {
        // v1 stored `entries: HashMap<String, String>` (path → hex hash).
        // Loaders must reject it cleanly so we don't conjure zero-metadata
        // fast-path skips on entries that never had real metadata.
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");
        let v1 = serde_json::json!({
            "version": 1,
            "entries": { "/foo": "ab".repeat(32) }
        });
        std::fs::write(&cache_path, serde_json::to_vec(&v1).unwrap()).unwrap();
        assert!(MerkleIndex::load(&cache_path).is_empty());
    }

    #[test]
    fn save_with_spec_then_load_with_matching_spec_keeps_entries() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");
        let idx = MerkleIndex::empty();
        let p = PathBuf::from("/tmp/x");
        let h = sample_hash(b"x");
        idx.record_with_metadata(p.clone(), 7, 1, h);
        let spec = [42u8; 32];
        idx.save_with_spec(&cache_path, &spec).unwrap();
        let loaded = MerkleIndex::load_with_spec(&cache_path, &spec);
        assert_eq!(loaded.len(), 1);
        assert!(loaded.metadata_unchanged(&p, 7, 1));
    }

    #[test]
    fn load_with_mismatched_spec_invalidates_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");
        let idx = MerkleIndex::empty();
        idx.record_with_metadata(PathBuf::from("/tmp/x"), 7, 1, sample_hash(b"x"));
        idx.save_with_spec(&cache_path, &[42u8; 32]).unwrap();
        // Different spec hash → empty cache.
        let loaded = MerkleIndex::load_with_spec(&cache_path, &[7u8; 32]);
        assert!(loaded.is_empty());
    }

    #[test]
    fn load_with_spec_when_disk_has_no_spec_invalidates() {
        // Old save() (no spec) must NOT satisfy a load_with_spec gate —
        // missing means "we don't know which detector set wrote this,"
        // so treat as cold-start under the strict path.
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");
        let idx = MerkleIndex::empty();
        idx.record_with_metadata(PathBuf::from("/tmp/x"), 1, 1, sample_hash(b"x"));
        idx.save(&cache_path).unwrap();
        let loaded = MerkleIndex::load_with_spec(&cache_path, &[1u8; 32]);
        assert!(loaded.is_empty());
    }

    #[test]
    fn compute_spec_hash_is_stable_under_reordering() {
        use crate::spec::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
        let make = |id: &str| DetectorSpec {
            id: id.to_string(),
            name: id.to_string(),
            service: id.to_string(),
            severity: Severity::Medium,
            keywords: vec![],
            patterns: vec![PatternSpec {
                regex: format!("{id}-[A-Z]+"),
                description: None,
                group: None,
            }],
            companions: vec![CompanionSpec {
                name: "k".into(),
                regex: "v=([A-Z]+)".into(),
                within_lines: 3,
                required: false,
            }],
            verify: None,
        };
        let a = compute_spec_hash(&[make("alpha"), make("beta")]);
        let b = compute_spec_hash(&[make("beta"), make("alpha")]);
        assert_eq!(a, b, "spec hash must be order-invariant");

        let c = compute_spec_hash(&[make("alpha"), make("gamma")]);
        assert_ne!(a, c, "different detectors must produce different hashes");
    }

    #[test]
    fn save_merges_with_existing_disk_entries() {
        // Simulates two concurrent `keyhog scan --incremental`
        // processes scanning different subsets. The save path now
        // does read-modify-write so process B's save doesn't blow
        // away process A's entries when their target path sets
        // don't overlap.
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");
        let spec = [42u8; 32];

        // Process A scans path /a/file and saves.
        let idx_a = MerkleIndex::empty();
        idx_a.record_with_metadata(
            PathBuf::from("/a/file"),
            100,
            10,
            sample_hash(b"a contents"),
        );
        idx_a.save_with_spec(&cache_path, &spec).unwrap();

        // Process B (separate handle, fresh memory) scans /b/file and
        // saves. Without read-modify-write, /a/file's entry would be
        // gone after this save.
        let idx_b = MerkleIndex::empty();
        idx_b.record_with_metadata(
            PathBuf::from("/b/file"),
            200,
            20,
            sample_hash(b"b contents"),
        );
        idx_b.save_with_spec(&cache_path, &spec).unwrap();

        // Reload with the same spec. BOTH /a/file AND /b/file must
        // be present — process A's entry survived process B's save.
        let loaded = MerkleIndex::load_with_spec(&cache_path, &spec);
        assert_eq!(loaded.len(), 2);
        assert!(loaded.metadata_unchanged(Path::new("/a/file"), 100, 10));
        assert!(loaded.metadata_unchanged(Path::new("/b/file"), 200, 20));
    }

    #[test]
    fn save_overwrites_disk_entry_for_same_path() {
        // The merge is "in-memory wins" — if both disk and memory
        // hold a record for the same path, the freshly-saved one
        // (memory) takes precedence. Otherwise a stale disk entry
        // could "resurrect" itself across saves and never get
        // updated.
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");
        let spec = [42u8; 32];

        let idx_old = MerkleIndex::empty();
        idx_old.record_with_metadata(
            PathBuf::from("/x"),
            100,
            10,
            sample_hash(b"old"),
        );
        idx_old.save_with_spec(&cache_path, &spec).unwrap();

        let idx_new = MerkleIndex::empty();
        idx_new.record_with_metadata(
            PathBuf::from("/x"),
            200,
            20,
            sample_hash(b"new"),
        );
        idx_new.save_with_spec(&cache_path, &spec).unwrap();

        let loaded = MerkleIndex::load_with_spec(&cache_path, &spec);
        assert_eq!(loaded.len(), 1);
        // The mtime/size from idx_new must be the surviving copy.
        assert!(loaded.metadata_unchanged(Path::new("/x"), 200, 20));
        assert!(!loaded.metadata_unchanged(Path::new("/x"), 100, 10));
    }

    #[test]
    fn save_drops_stale_spec_entries_on_disk() {
        // If the on-disk file was written with a DIFFERENT detector
        // spec, those entries are stale (a future load_with_spec
        // would invalidate them anyway). The save path uses
        // load_with_spec internally, so spec-mismatched disk entries
        // are NOT merged in — only the current process's in-memory
        // entries get written.
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");

        let idx_old = MerkleIndex::empty();
        idx_old.record_with_metadata(
            PathBuf::from("/from-old-spec"),
            1,
            1,
            sample_hash(b"x"),
        );
        idx_old.save_with_spec(&cache_path, &[1u8; 32]).unwrap();

        let idx_new = MerkleIndex::empty();
        idx_new.record_with_metadata(
            PathBuf::from("/from-new-spec"),
            2,
            2,
            sample_hash(b"y"),
        );
        idx_new.save_with_spec(&cache_path, &[2u8; 32]).unwrap();

        // After saving with the new spec, only the new-spec entry
        // is present. The old-spec entry was dropped at save time.
        let loaded = MerkleIndex::load_with_spec(&cache_path, &[2u8; 32]);
        assert_eq!(loaded.len(), 1);
        assert!(loaded.metadata_unchanged(Path::new("/from-new-spec"), 2, 2));
    }
}
