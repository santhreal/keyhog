//! Git repository source: scans repository commits and extracts text blobs with
//! `gix`, stopping once the in-memory byte cap is reached.

use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use gix::objs::Kind;
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use rayon::prelude::*;

/// Upper bound for one parallel blob decode batch.
///
/// Git object bytes are decompressed into owned `String`s before the iterator
/// drains them into chunks, so this is intentionally much lower than the full
/// history cap. It keeps the parallel path from reintroducing the "collect the
/// whole tree" memory spike that the serial cap loop removed.
const GIT_PARALLEL_BLOB_BATCH_BYTES: u64 = 32 * 1024 * 1024;

/// Metadata item bound for one parallel blob decode batch.
const GIT_PARALLEL_BLOB_BATCH_ITEMS: usize = 4096;

#[derive(Debug, Clone)]
struct GitBlobCandidate {
    oid: gix::ObjectId,
    filepath: Vec<u8>,
    size_bytes: u64,
}

#[derive(Debug)]
struct DecodedGitBlob {
    oid: gix::ObjectId,
    filepath: Vec<u8>,
    size_bytes: u64,
    file_text: String,
}

#[derive(Debug)]
enum GitBlobBatchItem {
    Candidate(GitBlobCandidate),
    Skip(GitBlobSkip),
}

#[derive(Debug)]
enum GitBlobDecodeOutcome {
    Decoded(DecodedGitBlob),
    Skip(GitBlobSkip),
}

#[derive(Debug)]
enum GitBlobSkip {
    HeaderUnreadable {
        oid: gix::ObjectId,
        error: String,
    },
    OverMaxSize {
        oid: gix::ObjectId,
        size: u64,
        cap: u64,
    },
    RepositoryOpen {
        oid: gix::ObjectId,
        error: String,
    },
    ObjectUnreadable {
        oid: gix::ObjectId,
        error: String,
    },
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitHistoryCap {
    TotalBytes { total: usize, cap: usize },
    Chunks { count: usize, cap: usize },
}

fn git_history_cap_status(
    total_bytes: usize,
    chunk_count: usize,
    limits: crate::SourceLimits,
) -> Option<GitHistoryCap> {
    if total_bytes >= limits.git_total_bytes {
        return Some(GitHistoryCap::TotalBytes {
            total: total_bytes,
            cap: limits.git_total_bytes,
        });
    }
    if chunk_count >= limits.git_chunk_count {
        return Some(GitHistoryCap::Chunks {
            count: chunk_count,
            cap: limits.git_chunk_count,
        });
    }
    None
}

fn record_git_history_cap_once(cap: GitHistoryCap, reported: &mut bool) {
    if *reported {
        return;
    }
    *reported = true;
    match cap {
        GitHistoryCap::TotalBytes { total, cap } => {
            tracing::warn!(
                total_bytes = total,
                cap,
                "git history source reached aggregate byte cap; remaining blobs were NOT scanned"
            );
        }
        GitHistoryCap::Chunks { count, cap } => {
            tracing::warn!(
                chunks = count,
                cap,
                "git history source reached aggregate chunk cap; remaining blobs were NOT scanned"
            );
        }
    }
    let _event = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
}

pub(crate) fn record_git_history_cap_for_test(total_bytes: usize, chunk_count: usize) -> bool {
    let Some(cap) =
        git_history_cap_status(total_bytes, chunk_count, crate::SourceLimits::default())
    else {
        return false;
    };
    let mut reported = false;
    record_git_history_cap_once(cap, &mut reported);
    reported
}

/// Scans git blobs reachable from refs, reflogs, stashes, and dangling commits.
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
    limits: crate::SourceLimits,
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
            limits: crate::SourceLimits::default(),
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

    pub fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl Source for GitSource {
    fn name(&self) -> &str {
        "git"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match stream_git_blobs(&self.repo_path, self.max_commits, self.limits) {
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
    limits: crate::SourceLimits,
) -> Result<impl Iterator<Item = Result<Chunk, SourceError>>, SourceError> {
    let repo_arg = super::validate_repo_path(repo_path)?;

    // Get commit hashes from refs plus reflogs. `--all` alone misses deleted
    // branch reflog commits on current Git, and it also misses refs/stash on
    // some versions, so stash is added explicitly when present.
    let mut log_cmd = Command::new(super::git_bin()?);
    log_cmd.args([
        "-C",
        &repo_arg,
        "log",
        "--reflog",
        "--all",
        "--date-order",
        "-m", // emit patches for merge commits ("evil merges")
        "--format=%H",
    ]);
    if let Some(limit) = max_commits {
        log_cmd.args(["--max-count", &limit.to_string()]);
    }
    log_cmd.arg("--end-of-options");
    if git_ref_exists(&repo_arg, "refs/stash")? {
        log_cmd.arg("refs/stash");
    }

    log_cmd.stdout(std::process::Stdio::piped());
    log_cmd.stderr(std::process::Stdio::piped());
    let mut log_child = log_cmd.spawn().map_err(SourceError::Io)?;
    let log_stdout = log_child
        .stdout
        .take()
        .ok_or_else(|| SourceError::Io(std::io::Error::other("missing log stdout")))?;
    let mut log_lines = std::io::BufReader::new(log_stdout).lines();

    // Open the gix repo ONCE and reuse it for every commit. The previous
    // version called `gix::open(&repo_owned)` per-commit which on a 10k-commit
    // repo opened the repo 10k times - fd churn + IO amplification.
    let repo_owned = PathBuf::from(&repo_arg);
    let repo_handle = gix::open(&repo_owned)
        .map_err(|e| SourceError::Io(std::io::Error::other(format!("gix open: {e}"))))?;
    // Snapshot every blob OID reachable from HEAD's tree. Used to label
    // emitted chunks as "git/head" (live in HEAD) vs "git/history"
    // (only present in older commits). The downstream scorer downgrades
    // the severity of `git/history` findings - a credential a developer
    // already removed from HEAD is still a leak, but less urgent than
    // one currently grep-able from main. Cheap: one tree walk at most.
    // Snapshot failures are source failures, not a severity-label guess. If
    // HEAD exists but its commit/tree cannot be read, labeling live blobs as
    // `git/history` would silently downgrade active leaks. The only clean empty
    // case is an unborn/empty repo, where there are no HEAD blobs to label.
    let head_blobs = collect_head_blob_set(&repo_handle)?;
    let mut current_tree_blobs: VecDeque<Chunk> = VecDeque::new();
    let mut seen_blobs: HashSet<gix::ObjectId> = HashSet::new();
    let mut seen_commits: HashSet<gix::ObjectId> = HashSet::new();
    let mut total_bytes = 0usize;
    let mut chunk_count = 0usize;
    let mut log_done = false;
    let mut unreachable_loaded = false;
    let mut unreachable_commits: VecDeque<gix::ObjectId> = VecDeque::new();
    let mut done = false;
    let mut aggregate_cap_reported = false;

    Ok(std::iter::from_fn(move || {
        if done {
            return None;
        }

        loop {
            if let Some(chunk) = current_tree_blobs.pop_front() {
                return Some(Ok(chunk));
            }

            if let Some(cap) = git_history_cap_status(total_bytes, chunk_count, limits) {
                record_git_history_cap_once(cap, &mut aggregate_cap_reported);
                done = true;
                return None;
            }

            let id = if let Some(id) = unreachable_commits.pop_front() {
                id
            } else if !log_done {
                match log_lines.next() {
                    Some(Ok(line)) => match parse_commit_id_line(&line) {
                        Ok(Some(id)) => id,
                        Ok(None) => continue,
                        Err(error) => {
                            done = true;
                            return Some(Err(error));
                        }
                    },
                    Some(Err(e)) => {
                        done = true;
                        return Some(Err(SourceError::Io(e)));
                    }
                    None => {
                        log_done = true;
                        if let Err(error) = wait_for_git_child(&mut log_child, "git log") {
                            done = true;
                            return Some(Err(error));
                        }
                        continue;
                    }
                }
            } else if !unreachable_loaded {
                let remaining = max_commits.map(|limit| limit.saturating_sub(seen_commits.len()));
                unreachable_loaded = true;
                match collect_unreachable_commit_ids(&repo_arg, remaining) {
                    Ok(ids) => unreachable_commits = ids,
                    Err(error) => {
                        done = true;
                        return Some(Err(error));
                    }
                }
                match unreachable_commits.pop_front() {
                    Some(id) => id,
                    None => {
                        done = true;
                        return None;
                    }
                }
            } else {
                done = true;
                return None;
            };

            let repo = &repo_handle;
            // Cache visited Git commit OIDs in a fast set to avoid traversing duplicate merge commits (KH-56)
            if !seen_commits.insert(id) {
                continue;
            }
            let commit_id_str = id.to_string();
            // Law 10: `git log` already enumerated this commit, so a gix failure to
            // load its object / commit / tree means a commit's blobs are NOT
            // scanned (corrupt object, partial clone missing the tree). Count each
            // as unreadable + warn so the dropped commit is operator-visible rather
            // than a silent `continue` that reads as full history coverage.
            let obj = match repo.find_object(id) {
                Ok(o) => o,
                Err(error) => {
                    tracing::warn!(%error, commit = %commit_id_str, "git commit object unreadable; its blobs were NOT scanned");
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                    continue;
                }
            };
            let commit = match obj.try_into_commit() {
                Ok(c) => c,
                Err(error) => {
                    tracing::warn!(%error, commit = %commit_id_str, "git object is not a commit; its blobs were NOT scanned");
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                    continue;
                }
            };
            let author_str = commit_author_name(&commit, &commit_id_str);
            let tree = match commit.tree() {
                Ok(t) => t,
                Err(error) => {
                    tracing::warn!(%error, commit = %commit_id_str, "git commit tree unreadable; its blobs were NOT scanned");
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                    continue;
                }
            };

            let mut blob_metadata = Vec::new();
            collect_tree_blobs_metadata(repo, &tree, &mut seen_blobs, &mut blob_metadata, b"");

            if !blob_metadata.is_empty() {
                let mut blob_metadata = blob_metadata.into_iter();
                let head_blobs_ref = &head_blobs;

                'blob_batches: loop {
                    if git_history_cap_status(total_bytes, chunk_count, limits).is_some() {
                        break;
                    }

                    let batch = next_git_blob_batch(repo, &mut blob_metadata, limits);
                    if batch.is_empty() {
                        break;
                    }

                    let candidates = batch
                        .iter()
                        .filter_map(|item| match item {
                            GitBlobBatchItem::Candidate(candidate) => Some(candidate.clone()),
                            GitBlobBatchItem::Skip(_) => None,
                        })
                        .collect::<Vec<_>>();
                    let mut decoded =
                        decode_git_blob_candidates_parallel(&repo_owned, candidates).into_iter();

                    for item in batch {
                        if git_history_cap_status(total_bytes, chunk_count, limits).is_some() {
                            break 'blob_batches;
                        }

                        let decoded_blob = match item {
                            GitBlobBatchItem::Skip(skip) => {
                                record_git_blob_skip(skip);
                                continue;
                            }
                            GitBlobBatchItem::Candidate(candidate) => match decoded.next() {
                                Some(GitBlobDecodeOutcome::Decoded(decoded_blob)) => decoded_blob,
                                Some(GitBlobDecodeOutcome::Skip(skip)) => {
                                    record_git_blob_skip(skip);
                                    continue;
                                }
                                None => {
                                    tracing::warn!(
                                        %candidate.oid,
                                        "git blob decode batch lost an outcome; blob NOT scanned"
                                    );
                                    let _event = crate::record_skip_event(
                                        crate::SourceSkipEvent::Unreadable,
                                    );
                                    continue;
                                }
                            },
                        };

                        let path = String::from_utf8_lossy(&decoded_blob.filepath).to_string();
                        let in_head = head_blobs_ref.contains(&decoded_blob.oid);
                        let chunk = Chunk {
                            data: decoded_blob.file_text.into(),
                            metadata: ChunkMetadata {
                                base_offset: 0,
                                base_line: 0,
                                source_type: if in_head { "git/head" } else { "git/history" }
                                    .into(),
                                path: Some(path),
                                commit: Some(commit_id_str.clone()),
                                author: Some(author_str.clone()),
                                date: None,
                                mtime_ns: None,
                                size_bytes: Some(decoded_blob.size_bytes),
                                decoded_span: None,
                            },
                        };
                        total_bytes = total_bytes.saturating_add(chunk.data.len());
                        chunk_count += 1;
                        current_tree_blobs.push_back(chunk);
                    }
                }

                if let Some(chunk) = current_tree_blobs.pop_front() {
                    return Some(Ok(chunk));
                }
            }
        }
    }))
}

fn next_git_blob_batch(
    repo: &gix::Repository,
    blob_metadata: &mut std::vec::IntoIter<(gix::ObjectId, Vec<u8>)>,
    limits: crate::SourceLimits,
) -> Vec<GitBlobBatchItem> {
    let mut batch = Vec::new();
    let mut batch_bytes = 0u64;
    let mut batch_items = 0usize;

    while batch_items < GIT_PARALLEL_BLOB_BATCH_ITEMS && batch_bytes < GIT_PARALLEL_BLOB_BATCH_BYTES
    {
        let Some((oid, filepath)) = blob_metadata.next() else {
            break;
        };
        batch_items += 1;

        let header = match repo.find_header(oid) {
            Ok(header) => header,
            Err(error) => {
                batch.push(GitBlobBatchItem::Skip(GitBlobSkip::HeaderUnreadable {
                    oid,
                    error: error.to_string(),
                }));
                continue;
            }
        };

        if header.kind() != Kind::Blob {
            continue;
        }

        let size_bytes = header.size();
        if size_bytes > limits.git_blob_bytes {
            batch.push(GitBlobBatchItem::Skip(GitBlobSkip::OverMaxSize {
                oid,
                size: size_bytes,
                cap: limits.git_blob_bytes,
            }));
            continue;
        }

        batch_bytes = batch_bytes.saturating_add(size_bytes);
        batch.push(GitBlobBatchItem::Candidate(GitBlobCandidate {
            oid,
            filepath,
            size_bytes,
        }));
    }

    batch
}

fn decode_git_blob_candidates_parallel(
    repo_path: &Path,
    candidates: Vec<GitBlobCandidate>,
) -> Vec<GitBlobDecodeOutcome> {
    let repo_path = repo_path.to_path_buf();
    candidates
        .into_par_iter()
        .map_init(
            || gix::open(&repo_path).map_err(|error| error.to_string()),
            |repo_state, candidate| match repo_state {
                Ok(repo) => decode_git_blob_candidate(repo, candidate),
                Err(error) => GitBlobDecodeOutcome::Skip(GitBlobSkip::RepositoryOpen {
                    oid: candidate.oid,
                    error: error.clone(),
                }),
            },
        )
        .collect()
}

fn decode_git_blob_candidate(
    repo: &gix::Repository,
    candidate: GitBlobCandidate,
) -> GitBlobDecodeOutcome {
    let obj = match repo.find_object(candidate.oid) {
        Ok(object) => object,
        Err(error) => {
            return GitBlobDecodeOutcome::Skip(GitBlobSkip::ObjectUnreadable {
                oid: candidate.oid,
                error: error.to_string(),
            });
        }
    };

    let Some(file_text) = decode_git_blob(&obj.data) else {
        return GitBlobDecodeOutcome::Skip(GitBlobSkip::Binary);
    };

    GitBlobDecodeOutcome::Decoded(DecodedGitBlob {
        oid: candidate.oid,
        filepath: candidate.filepath,
        size_bytes: candidate.size_bytes,
        file_text,
    })
}

fn record_git_blob_skip(skip: GitBlobSkip) {
    match skip {
        GitBlobSkip::HeaderUnreadable { oid, error } => {
            // Law 10: the blob is referenced by the tree but its object header
            // could not be read. It is not scanned, so count it as unreadable.
            tracing::warn!(
                %error, %oid,
                "git blob header unreadable (corrupt/missing object); blob NOT scanned"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        }
        GitBlobSkip::OverMaxSize { oid, size, cap } => {
            tracing::warn!(
                %oid,
                size,
                cap,
                "git blob exceeds the per-blob size cap; NOT scanned"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        }
        GitBlobSkip::RepositoryOpen { oid, error } => {
            tracing::warn!(
                %error, %oid,
                "git repository could not be opened by a blob decode worker; blob NOT scanned"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        }
        GitBlobSkip::ObjectUnreadable { oid, error } => {
            tracing::warn!(
                %error, %oid,
                "git blob object unreadable (corrupt/missing object); blob NOT scanned"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        }
        GitBlobSkip::Binary => {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
        }
    }
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

fn git_ref_exists(repo_arg: &str, ref_name: &str) -> Result<bool, SourceError> {
    let output = Command::new(super::git_bin()?)
        .args([
            "-C",
            repo_arg,
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
        ])
        .arg(format!("{ref_name}^{{commit}}"))
        .output()
        .map_err(SourceError::Io)?;
    Ok(output.status.success())
}

fn parse_commit_id_line(line: &str) -> Result<Option<gix::ObjectId>, SourceError> {
    let Some(commit_id) = line.split_whitespace().next() else {
        return Ok(None);
    };
    match gix::ObjectId::from_hex(commit_id.as_bytes()) {
        Ok(id) => Ok(Some(id)),
        Err(error) => {
            tracing::warn!(
                %error,
                commit = commit_id,
                "git reported an unparsable commit id; commit NOT scanned"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            Ok(None)
        }
    }
}

fn wait_for_git_child(child: &mut std::process::Child, label: &str) -> Result<(), SourceError> {
    let status = child.wait().map_err(SourceError::Io)?;
    if status.success() {
        return Ok(());
    }

    let mut stderr = String::new();
    if let Some(stderr_pipe) = child.stderr.as_mut() {
        if let Err(error) = stderr_pipe.read_to_string(&mut stderr) {
            stderr = format!("stderr unavailable: {error}");
        }
    }
    Err(SourceError::Git(format!(
        "{label} failed while enumerating git commits: {}",
        stderr.trim()
    )))
}

fn collect_unreachable_commit_ids(
    repo_arg: &str,
    remaining: Option<usize>,
) -> Result<VecDeque<gix::ObjectId>, SourceError> {
    if remaining == Some(0) {
        return Ok(VecDeque::new());
    }

    let output = Command::new(super::git_bin()?)
        .args([
            "-C",
            repo_arg,
            "fsck",
            "--unreachable",
            "--no-reflogs",
            "--no-progress",
        ])
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SourceError::Git(format!(
            "git fsck failed while enumerating unreachable commits: {}",
            stderr.trim()
        )));
    }

    let mut out = VecDeque::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some(commit_id) = line.strip_prefix("unreachable commit ") else {
            continue;
        };
        let Some(id) = parse_commit_id_line(commit_id)? else {
            continue;
        };
        out.push_back(id);
        if remaining.is_some_and(|limit| out.len() >= limit) {
            break;
        }
    }
    Ok(out)
}

fn commit_author_name(commit: &gix::Commit<'_>, commit_id: &str) -> String {
    match commit.author() {
        Ok(author) => {
            let name = String::from_utf8_lossy(author.name.as_ref())
                .trim()
                .to_string();
            if name.is_empty() {
                "unknown".to_string()
            } else {
                name
            }
        }
        Err(error) => {
            tracing::warn!(
                %error,
                commit = commit_id,
                "git commit author metadata unreadable; chunk author set to unknown"
            );
            "unknown".to_string()
        }
    }
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
                // Law 10: a tree entry that fails to parse (corrupt/truncated tree
                // object) means the blob(s) it would reference are NOT scanned — an
                // UNKNOWN, not a clean tree. The old `tracing::debug!` was invisible
                // at default verbosity, so the dropped blobs vanished from coverage
                // with no trace. Surface loudly + count as unreadable so a "0
                // findings --git" run is not mistaken for full history coverage.
                tracing::warn!(
                    %error,
                    "git tree entry could not be read (corrupt tree object); \
                     its blob(s) were NOT scanned"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                continue;
            }
        };

        let oid = entry.oid().to_owned();

        let filepath = if prefix.is_empty() {
            entry.filename().to_vec()
        } else {
            let mut p = prefix.to_vec();
            p.push(b'/');
            p.extend_from_slice(entry.filename());
            p
        };

        let default_exclude_path = String::from_utf8_lossy(&filepath);
        if crate::filesystem::is_default_excluded_path(default_exclude_path.as_ref()) {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Excluded);
            continue;
        }

        let mode = entry.mode();

        if mode.is_tree() {
            let obj = match repo.find_object(oid) {
                Ok(obj) => obj,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "git subtree object unreadable; its blob(s) were NOT scanned"
                    );
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                    continue;
                }
            };
            match obj.try_into_tree() {
                Ok(subtree) => {
                    collect_tree_blobs_metadata(
                        repo,
                        &subtree,
                        seen_blobs,
                        blob_metadata,
                        &filepath,
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "git tree entry resolved to a non-tree object; its blob(s) were NOT scanned"
                    );
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
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
/// Returns an empty set for an unborn/empty repository. Any failure after HEAD
/// resolves is a source error: otherwise live HEAD blobs can be mislabeled as
/// `git/history`, silently downgrading active leaks.
fn collect_head_blob_set(repo: &gix::Repository) -> Result<HashSet<gix::ObjectId>, SourceError> {
    let head = match repo.head() {
        Ok(head) => head,
        Err(error) => {
            tracing::debug!(
                %error,
                "git: HEAD is unavailable while collecting HEAD blob set; treating repository as empty"
            );
            return Ok(HashSet::new());
        }
    };
    let Some(head_id) = head.try_into_peeled_id().map_err(|error| {
        SourceError::Git(format!(
            "failed to resolve git HEAD while collecting live blob set: {error}"
        ))
    })?
    else {
        return Ok(HashSet::new());
    };
    let commit = repo
        .find_object(head_id)
        .map_err(|error| {
            SourceError::Git(format!(
                "failed to read git HEAD object while collecting live blob set: {error}"
            ))
        })?
        .try_into_commit()
        .map_err(|error| {
            SourceError::Git(format!(
                "git HEAD object is not a commit while collecting live blob set: {error}"
            ))
        })?;
    let tree = commit.tree().map_err(|error| {
        SourceError::Git(format!(
            "failed to read git HEAD tree while collecting live blob set: {error}"
        ))
    })?;
    let mut out = HashSet::new();
    walk_tree_for_blobs(repo, &tree, &mut out)?;
    Ok(out)
}

fn walk_tree_for_blobs(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
    out: &mut HashSet<gix::ObjectId>,
) -> Result<(), SourceError> {
    for entry_ref in tree.iter() {
        let entry = entry_ref.map_err(|error| {
            SourceError::Git(format!(
                "failed to read git HEAD tree entry while collecting live blob set: {error}"
            ))
        })?;
        let oid = entry.oid().to_owned();
        let mode = entry.mode();
        if mode.is_tree() {
            let obj = repo.find_object(oid).map_err(|error| {
                SourceError::Git(format!(
                    "failed to read git HEAD subtree object while collecting live blob set: {error}"
                ))
            })?;
            let subtree = obj.try_into_tree().map_err(|error| {
                SourceError::Git(format!(
                    "git HEAD subtree object is not a tree while collecting live blob set: {error}"
                ))
            })?;
            walk_tree_for_blobs(repo, &subtree, out)?;
        } else if mode.is_blob() {
            out.insert(oid);
        }
    }
    Ok(())
}
