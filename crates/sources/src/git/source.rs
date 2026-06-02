//! Git repository source: scans repository commits and extracts text blobs with
//! `gix`, stopping once the in-memory byte cap is reached.

use std::collections::{HashSet, VecDeque};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::Command;

use gix::objs::Kind;
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};

/// Maximum total in-memory bytes for all git blob content.
/// 256 MiB covers large monorepos without OOM.
const MAX_GIT_TOTAL_BYTES: usize = 256 * 1024 * 1024;

/// Maximum size of a single git blob. Larger objects (binaries, vendor bundles)
/// are skipped entirely - secrets almost never appear in 10+ MiB files.
const MAX_GIT_BLOB_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum number of chunks the git source can produce.
/// Guards against repos with millions of tiny files where the byte limit alone
/// wouldn't cap memory: each chunk carries ~200 bytes of metadata overhead,
/// so 500K chunks × 200B = ~100 MB metadata ceiling.
const MAX_GIT_CHUNKS: usize = 500_000;

/// Scans git history: traverses commits and extracts text blob contents.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::Source;
/// use keyhog_sources::GitSource;
/// use std::path::PathBuf;
///
/// let source = GitSource::new(PathBuf::from(".")).with_max_commits(10);
/// assert_eq!(source.name(), "git");
/// ```
pub struct GitSource {
    repo_path: PathBuf,
    max_commits: Option<usize>,
}

impl GitSource {
    /// Create a source that traverses a git repository.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::GitSource;
    /// use std::path::PathBuf;
    ///
    /// let source = GitSource::new(PathBuf::from("."));
    /// assert_eq!(source.name(), "git");
    /// ```
    pub fn new(repo_path: PathBuf) -> Self {
        Self {
            repo_path,
            max_commits: None,
        }
    }

    /// Limit how many commits are traversed from `HEAD`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::GitSource;
    /// use std::path::PathBuf;
    ///
    /// let source = GitSource::new(PathBuf::from(".")).with_max_commits(5);
    /// assert_eq!(source.name(), "git");
    /// ```
    pub fn with_max_commits(mut self, n: usize) -> Self {
        self.max_commits = Some(n);
        self
    }
}

impl Source for GitSource {
    fn name(&self) -> &str {
        "git"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match stream_git_blobs(&self.repo_path, self.max_commits) {
            Ok(iter) => Box::new(iter),
            Err(e) => Box::new(std::iter::once(Err(e))),
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn stream_git_blobs(
    repo_path: &Path,
    max_commits: Option<usize>,
) -> Result<impl Iterator<Item = Result<Chunk, SourceError>>, SourceError> {
    let repo_arg = super::validate_repo_path(repo_path)?;

    // Get commit hashes from ALL refs - branches, tags, dangling commits.
    // The previous version walked HEAD ancestry only, silently missing
    // secrets in feature branches, deleted-but-tagged history, and merge-only
    // commits. See audit release-2026-04-26 sources/git/source.rs:104.
    let mut log_cmd = Command::new(super::git_bin()?);
    log_cmd.args([
        "-C",
        &repo_arg,
        "log",
        "--all",
        "--branches",
        "--tags",
        "-m", // emit patches for merge commits ("evil merges")
        "--format=%H %an",
    ]);
    if let Some(limit) = max_commits {
        log_cmd.args(["--max-count", &limit.to_string()]);
    }
    log_cmd.arg("--end-of-options");

    log_cmd.stdout(std::process::Stdio::piped());
    let mut log_child = log_cmd.spawn().map_err(SourceError::Io)?;
    let log_stdout = log_child
        .stdout
        .take()
        .ok_or_else(|| SourceError::Io(std::io::Error::other("missing log stdout")))?;
    let mut log_lines = std::io::BufReader::new(log_stdout).lines();

    // Open the gix repo ONCE and reuse it for every commit. The previous
    // version called `gix::open(&repo_owned)` per-commit which on a 10k-commit
    // repo opened the repo 10k times - fd churn + IO amplification.
    let repo_owned = repo_path.to_path_buf();
    let repo_handle = gix::open(&repo_owned)
        .map_err(|e| SourceError::Io(std::io::Error::other(format!("gix open: {e}"))))?;
    // Snapshot every blob OID reachable from HEAD's tree. Used to label
    // emitted chunks as "git/head" (live in HEAD) vs "git/history"
    // (only present in older commits). The downstream scorer downgrades
    // the severity of `git/history` findings - a credential a developer
    // already removed from HEAD is still a leak, but less urgent than
    // one currently grep-able from main. Cheap: one tree walk at most.
    // If the HEAD blob walk fails (corrupt object, unborn HEAD, partial
    // clone without the tree objects) we fall back to an empty set,
    // which labels every chunk as `git/history`. The downstream scorer
    // downgrades that bucket, so a silent failure here would
    // systematically deflate severity for findings that are actually
    // live in HEAD. Surface the missing set so the operator sees the
    // cause and can fall back to `keyhog scan --git-staged` or
    // `--git-diff` instead.
    let head_blobs = match collect_head_blob_set(&repo_handle) {
        Some(set) => set,
        None => {
            tracing::warn!(
                "git: HEAD blob walk produced no set; all findings will be \
                 labelled git/history (lower severity). The scan continues \
                 but you may underweight live-in-HEAD leaks. Common causes: \
                 unborn HEAD, partial clone without tree objects, \
                 corrupt ref."
            );
            HashSet::new()
        }
    };
    let mut current_tree_blobs: VecDeque<Chunk> = VecDeque::new();
    let mut seen_blobs: HashSet<gix::ObjectId> = HashSet::new();
    let mut seen_commits: HashSet<gix::ObjectId> = HashSet::new();
    let mut total_bytes = 0usize;
    let mut chunk_count = 0usize;
    let mut done = false;

    Ok(std::iter::from_fn(move || {
        if done {
            return None;
        }

        loop {
            if let Some(chunk) = current_tree_blobs.pop_front() {
                return Some(Ok(chunk));
            }

            if total_bytes >= MAX_GIT_TOTAL_BYTES || chunk_count >= MAX_GIT_CHUNKS {
                done = true;
                return None;
            }

            let line = match log_lines.next() {
                Some(Ok(l)) => l,
                Some(Err(e)) => {
                    done = true;
                    return Some(Err(SourceError::Io(e)));
                }
                None => {
                    done = true;
                    return None;
                }
            };

            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() < 2 {
                continue;
            }
            let commit_id = parts[0];
            let author = parts[1];

            let repo = &repo_handle;
            let Ok(id) = gix::ObjectId::from_hex(commit_id.as_bytes()) else {
                continue;
            };
            // Cache visited Git commit OIDs in a fast set to avoid traversing duplicate merge commits (KH-56)
            if !seen_commits.insert(id) {
                continue;
            }
            let Ok(obj) = repo.find_object(id) else {
                continue;
            };
            let Ok(commit) = obj.try_into_commit() else {
                continue;
            };
            let Ok(tree) = commit.tree() else {
                continue;
            };

            let mut blob_metadata = Vec::new();
            collect_tree_blobs_metadata(repo, &tree, &mut seen_blobs, &mut blob_metadata, b"");

            if !blob_metadata.is_empty() {
                let repo_cloned = repo.clone();
                let commit_id_str = commit_id.to_string();
                let author_str = author.to_string();
                let head_blobs_ref = &head_blobs;

                // Serial blob decompression. This was `into_par_iter()` (KH-58),
                // but `gix::Repository` (gix 0.77) holds RefCell-backed object/
                // pack caches: it is `Send` but NOT `Sync`, so sharing one across
                // Rayon worker threads does not compile. A fresh
                // `cargo build -p keyhog-sources --features git` failed with 7
                // `RefCell<…> cannot be shared between threads safely` errors -
                // which is why clean CI builds went red while cached local builds
                // still passed. Correct re-parallelization needs a per-thread
                // `gix::open(git_dir)` via `map_init` (each worker owns its own
                // Repository); tracked as a follow-up. Serial is correct and
                // keeps git history scanning working.
                //
                // Memory bound (M16): enforce the aggregate byte/chunk caps
                // INSIDE this per-commit loop rather than only between commits.
                // The previous `.collect()` materialized every unique blob in
                // the commit's reachable tree at once - for the initial commit
                // of a large monorepo that is the entire tree (multi-GiB),
                // blowing past MAX_GIT_TOTAL_BYTES before a single chunk drained.
                // Accumulate into `total_bytes`/`chunk_count` as each blob is
                // decoded and stop collecting the moment a cap is crossed.
                for (oid, filepath) in blob_metadata {
                    if total_bytes >= MAX_GIT_TOTAL_BYTES || chunk_count >= MAX_GIT_CHUNKS {
                        break;
                    }
                    // Reject blobs larger than max_file_size immediately by reading only the Git object header metadata (KH-66)
                    let Ok(header) = repo_cloned.find_header(oid) else {
                        continue;
                    };
                    if header.kind() != Kind::Blob || header.size() > MAX_GIT_BLOB_BYTES {
                        continue;
                    }
                    let Ok(obj) = repo_cloned.find_object(oid) else {
                        continue;
                    };
                    // Decode contract mirrors the filesystem source (C4): a
                    // single non-UTF-8 byte must NOT discard the whole blob, or
                    // `keyhog scan --git` silently under-recalls vs.
                    // `keyhog scan <dir>`. Skip only true binary; otherwise
                    // decode losslessly.
                    let Some(file_text) = decode_git_blob(&obj.data) else {
                        continue;
                    };
                    let path = String::from_utf8_lossy(&filepath).to_string();
                    let in_head = head_blobs_ref.contains(&oid);
                    let chunk = Chunk {
                        data: file_text.into(),
                        metadata: ChunkMetadata {
                            base_offset: 0,
                            source_type: if in_head { "git/head" } else { "git/history" }.into(),
                            path: Some(path),
                            commit: Some(commit_id_str.clone()),
                            author: Some(author_str.clone()),
                            date: None,
                            mtime_ns: None,
                            size_bytes: Some(header.size()),
                        },
                    };
                    total_bytes = total_bytes.saturating_add(chunk.data.len());
                    chunk_count += 1;
                    current_tree_blobs.push_back(chunk);
                }

                if let Some(chunk) = current_tree_blobs.pop_front() {
                    return Some(Ok(chunk));
                }
            }
        }
    }))
}

/// Decode a git blob into scannable text using the same recall-preserving
/// contract as the filesystem source (`crate::filesystem::read::decode`).
///
/// The previous implementation used `std::str::from_utf8(&data).ok()?`, which
/// dropped the ENTIRE blob on a single non-UTF-8 byte - so a credential next to
/// a stray `0x80` (latin-1 config, a `.env` with a smart quote, a key beside
/// binary data) was found by `keyhog scan <dir>` but MISSED by
/// `keyhog scan --git` on the same content (audit C4). The filesystem path
/// instead falls back to `String::from_utf8_lossy` after a binary-density
/// check; mirror that here so non-UTF-8 blobs are still scanned.
///
/// Returns `None` only for true binary (recognized magic header or a high
/// density of C0 control bytes), matching `decode_text_file`'s rejects - those
/// inputs cannot carry a grep-able credential and would only add noise.
fn decode_git_blob(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return Some(String::new());
    }
    // Reject genuine binary FIRST. A NUL byte (and other C0 controls) is valid
    // UTF-8, so the fast path below would otherwise emit a NUL- or control-heavy
    // blob (ELF/PNG/sqlite/object files) as "text" and pay a full detector scan
    // on bytes that cannot carry a grep-able credential. Doing the cheap
    // first-1KiB heuristic up front mirrors the filesystem `decode_text_file`
    // ordering and skips that waste (precision + throughput).
    if looks_binary_blob(data) {
        return None;
    }
    // Valid-UTF-8 fast path (the common case for source trees): one validation
    // pass, owned copy on success.
    if let Ok(s) = std::str::from_utf8(data) {
        return Some(s.to_owned());
    }
    // Not strictly valid UTF-8 but not binary: partial corruption / latin-1 / a
    // stray high byte / UTF-16 — decode lossily to preserve recall (audit C4).
    Some(String::from_utf8_lossy(data).into_owned())
}

/// Cheap binary heuristic for git blobs, kept byte-compatible with the
/// filesystem `looks_binary` verdict: recognized magic headers, a NUL near the
/// start that isn't UTF-16's alternating pattern, or >5% C0 control density.
/// Lives here (rather than reaching into `crate::filesystem::read`, whose
/// helpers are module-private) so the git decode path stays self-contained.
fn looks_binary_blob(data: &[u8]) -> bool {
    // Common executable / archive / image / serialized-data magic bytes whose
    // contents cannot be a credential. Mirrors `has_binary_magic`.
    const MAGIC_HEADERS: &[&[u8]] = &[
        b"%PDF-",
        b"PK\x03\x04",
        b"\x89PNG\r\n\x1a\n",
        b"\xD0\xCF\x11\xE0",
        b"\x7fELF",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"MZ",
        b"\x1f\x8b",
        b"BZh",
        b"\xfd7zXZ\x00",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
        b"GIF87a",
        b"GIF89a",
        b"\xff\xd8\xff",
        b"\x00\x00\x01\x00",
        b"OggS",
        b"ID3",
        b"fLaC",
        b"\x00asm",
        b"!<arch>\n",
        b"\x80\x02",
    ];
    if MAGIC_HEADERS.iter().any(|h| data.starts_with(h)) {
        return true;
    }
    // UTF-16 BOM: alternating-NUL text, not binary.
    let utf16_bom = data.len() >= 4
        && ((data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF));
    if utf16_bom {
        return true;
    }
    // A NUL near the start usually means binary, unless it's headerless UTF-16
    // (alternating NULs), which is real text.
    if let Some(first_nul) = data.iter().position(|&b| b == 0) {
        if first_nul < 1024 {
            let is_utf16 = data.len() >= 4
                && ((data[0] == 0 && data[1] != 0) || (data[0] != 0 && data[1] == 0));
            if !is_utf16 {
                return true;
            }
        }
    }
    // C0-control density: >5% suspicious bytes (matching `looks_binary`'s
    // `suspicious * 20 > total` threshold).
    let total = data.len() as u64;
    if total == 0 {
        return false;
    }
    let mut suspicious: u64 = 0;
    for &byte in data {
        if byte < 0x20 && !matches!(byte, b'\n' | b'\r' | b'\t' | 0x0C) {
            suspicious += 1;
            if suspicious * 20 > total {
                return true;
            }
        }
    }
    false
}

fn collect_tree_blobs_metadata(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
    seen_blobs: &mut HashSet<gix::ObjectId>,
    blob_metadata: &mut Vec<(gix::ObjectId, Vec<u8>)>,
    prefix: &[u8],
) {
    for entry_ref in tree.iter() {
        let entry = match entry_ref {
            Ok(e) => e,
            Err(error) => {
                tracing::debug!(%error, "git tree entry read failed; skipping");
                continue;
            }
        };

        // Skip Git trees containing only excluded paths without reading individual blob OIDs (KH-59)
        let name = entry.filename();
        if name == b"node_modules"
            || name == b"target"
            || name == b".git"
            || name == b"__pycache__"
            || name == b"dist"
            || name == b"build"
            || name == b"vendor"
        {
            continue;
        }

        let oid = entry.oid().to_owned();

        let filepath = if prefix.is_empty() {
            entry.filename().to_vec()
        } else {
            let mut p = prefix.to_vec();
            p.push(b'/');
            p.extend_from_slice(entry.filename());
            p
        };

        let mode = entry.mode();

        if mode.is_tree() {
            if let Ok(obj) = repo.find_object(oid) {
                if let Ok(subtree) = obj.try_into_tree() {
                    collect_tree_blobs_metadata(
                        repo,
                        &subtree,
                        seen_blobs,
                        blob_metadata,
                        &filepath,
                    );
                }
            }
            continue;
        }

        if !mode.is_blob() {
            continue;
        }

        if seen_blobs.insert(oid) {
            blob_metadata.push((oid, filepath));
        }
    }
}

/// Walk HEAD's tree and collect every blob OID reachable from it.
///
/// Returns an empty set if HEAD doesn't resolve (detached, empty repo, or
/// transient I/O error). The caller's behavior in that case: every blob is
/// labeled `git/history` since we cannot prove it sits in HEAD - safer than
/// the inverse, which would suppress severity downgrades for genuine
/// historical leaks.
fn collect_head_blob_set(repo: &gix::Repository) -> Option<HashSet<gix::ObjectId>> {
    let head = repo.head().ok()?;
    let head_id = head.try_into_peeled_id().ok().flatten()?;
    let commit = repo.find_object(head_id).ok()?.try_into_commit().ok()?;
    let tree = commit.tree().ok()?;
    let mut out = HashSet::new();
    walk_tree_for_blobs(repo, &tree, &mut out);
    Some(out)
}

fn walk_tree_for_blobs(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
    out: &mut HashSet<gix::ObjectId>,
) {
    for entry_ref in tree.iter() {
        let Ok(entry) = entry_ref else { continue };
        let oid = entry.oid().to_owned();
        let mode = entry.mode();
        if mode.is_tree() {
            if let Ok(obj) = repo.find_object(oid) {
                if let Ok(subtree) = obj.try_into_tree() {
                    walk_tree_for_blobs(repo, &subtree, out);
                }
            }
        } else if mode.is_blob() {
            out.insert(oid);
        }
    }
}
