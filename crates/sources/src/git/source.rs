//! Git repository source: scans repository commits and extracts text blobs with
//! `gix`, stopping once the in-memory byte cap is reached.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::ChildStdout;

#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicUsize, Ordering};

use gix::objs::Kind;
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};

use super::tag_messages::{
    collect_reachable_tag_messages, decode_next_tag_message, decode_next_unreachable_tag_message,
};
use super::{git_unscanned_object_error, parse_git_object_id_line, record_git_object_unreadable};

/// Upper bound for one parallel blob decode batch.
///
/// Git object bytes are decompressed into owned `String`s before the iterator
/// drains them into chunks, so this is intentionally much lower than the full
/// history cap. It keeps the parallel path from reintroducing the "collect the
/// whole tree" memory spike that the serial cap loop removed.
const GIT_PARALLEL_BLOB_BATCH_BYTES: u64 = 32 * 1024 * 1024;

/// Metadata item bound for one parallel blob decode batch.
const GIT_PARALLEL_BLOB_BATCH_ITEMS: usize = 4096;

#[cfg(debug_assertions)]
static MAX_BUFFERED_GIT_BLOB_CHUNKS: AtomicUsize = AtomicUsize::new(0);

#[cfg(debug_assertions)]
pub(crate) fn reset_max_buffered_git_blob_chunks() {
    MAX_BUFFERED_GIT_BLOB_CHUNKS.store(0, Ordering::Relaxed);
}

#[cfg(debug_assertions)]
pub(crate) fn max_buffered_git_blob_chunks() -> usize {
    MAX_BUFFERED_GIT_BLOB_CHUNKS.load(Ordering::Relaxed)
}

#[cfg(debug_assertions)]
fn record_buffered_git_blob_chunks(chunks: usize) {
    MAX_BUFFERED_GIT_BLOB_CHUNKS.fetch_max(chunks, Ordering::Relaxed);
}

#[cfg(not(debug_assertions))]
fn record_buffered_git_blob_chunks(_chunks: usize) {}

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
    file_text: keyhog_core::SensitiveString,
}

/// Decoded text for one unique blob oid, shared by every (oid, path) slot
/// that references it so duplicate blob reads decode once and fan out cheap
/// `Arc` clones.
struct SharedDecodedBlob {
    size_bytes: u64,
    file_text: keyhog_core::SensitiveString,
}

/// Per-oid decode failure, without path identity: the same failure fans out
/// to every referencing (oid, path) slot, which re-attaches its own path so
/// per-path skip accounting is unchanged.
enum GitBlobOidSkipKind {
    ObjectUnreadable(String),
    Binary,
}

impl GitBlobOidSkipKind {
    fn with_identity(&self, oid: gix::ObjectId, filepath: Vec<u8>) -> GitBlobSkip {
        match self {
            Self::ObjectUnreadable(error) => GitBlobSkip::ObjectUnreadable {
                oid,
                filepath,
                error: error.clone(),
            },
            Self::Binary => GitBlobSkip::Binary { oid, filepath },
        }
    }
}

struct GitCommitBlobSet {
    commit_id: String,
    author: String,
    blob_metadata: Vec<(gix::ObjectId, Vec<u8>)>,
    errors: Vec<SourceError>,
}

struct PendingGitBlobDecode {
    blob_metadata: std::vec::IntoIter<(gix::ObjectId, Vec<u8>)>,
    provenance: PendingGitBlobProvenance,
}

enum PendingGitBlobProvenance {
    Commit { commit_id: String, author: String },
    Unreachable,
}

impl PendingGitBlobProvenance {
    fn borrowed(&self) -> GitBlobProvenance<'_> {
        match self {
            Self::Commit { commit_id, author } => GitBlobProvenance::Commit { commit_id, author },
            Self::Unreachable => GitBlobProvenance::Unreachable,
        }
    }
}

#[derive(Default)]
struct GitBlobMetadataBatch {
    metadata: Vec<(gix::ObjectId, Vec<u8>)>,
    errors: Vec<SourceError>,
}

#[derive(Default)]
struct UnreachableGitObjects {
    commits: VecDeque<gix::ObjectId>,
    blobs: VecDeque<gix::ObjectId>,
    trees: VecDeque<gix::ObjectId>,
    tags: VecDeque<gix::ObjectId>,
    tree_blob_oids: HashSet<gix::ObjectId>,
    truncated: bool,
}

impl UnreachableGitObjects {
    fn retained_object_count(&self) -> usize {
        self.commits.len() + self.blobs.len() + self.trees.len() + self.tags.len()
    }

    fn has_collection_capacity(&mut self, limits: crate::SourceLimits) -> bool {
        if self.retained_object_count() < limits.git_chunk_count {
            return true;
        }
        self.truncated = true;
        false
    }
}

type GitBlobPathKey = (gix::ObjectId, Vec<u8>);

#[derive(Debug)]
enum GitBlobBatchItem {
    Candidate(GitBlobCandidate),
    Skip(GitBlobSkip),
}

#[derive(Debug)]
enum GitBlobSkip {
    HeaderUnreadable {
        oid: gix::ObjectId,
        filepath: Vec<u8>,
        error: String,
    },
    NonBlob {
        oid: gix::ObjectId,
        filepath: Vec<u8>,
        kind: String,
    },
    OverMaxSize {
        oid: gix::ObjectId,
        filepath: Vec<u8>,
        size: u64,
        cap: u64,
    },
    ObjectUnreadable {
        oid: gix::ObjectId,
        filepath: Vec<u8>,
        error: String,
    },
    Binary {
        oid: gix::ObjectId,
        filepath: Vec<u8>,
    },
}

/// Scans git blobs reachable from refs, reflogs, stashes, dangling commits,
/// annotated tag messages, unreachable loose blobs, and unreachable tree/tag
/// objects.
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
    pub(crate) max_commits: Option<usize>,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
}

/// Single source of truth for the `with_max_commits` builder setting shared by
/// `GitSource` and `GitHistorySource`. Both builders store the requested commit
/// cap identically as `Some(n)`; centralizing the conversion here keeps the two
/// byte-identical setters from drifting and gives any future clamp/normalize
/// policy exactly one place to live. `history.rs` delegates via
/// `super::source::max_commits_limit`.
pub(crate) fn max_commits_limit(n: usize) -> Option<usize> {
    Some(n)
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
            respect_default_excludes: true,
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
        self.max_commits = max_commits_limit(n);
        self
    }

    pub fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_default_excludes(mut self, respect_default_excludes: bool) -> Self {
        self.respect_default_excludes = respect_default_excludes;
        self
    }
}

impl Source for GitSource {
    fn name(&self) -> &str {
        "git"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        crate::gate_scan(|| {
            // Top-level acquisition: repo validation, gix open, `git log`
            // spawn, tag collection, and the HEAD blob snapshot.
            let acquire = crate::profile::acquire_span();
            match stream_git_blobs(
                &self.repo_path,
                self.max_commits,
                self.limits,
                self.respect_default_excludes,
            ) {
                Ok(iter) => {
                    drop(acquire);
                    Box::new(iter.map(|row| {
                        crate::profile::record_emitted_chunk(&row);
                        row
                    }))
                }
                Err(e) => Box::new(std::iter::once(Err(e))),
            }
        })
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct GitCommitEnumerator {
    repo_arg: String,
    max_commits: Option<usize>,
    log_child: super::GitChild,
    // Capped line reader over `git log` stdout: `read_capped_line` bounds each
    // line at `GIT_PLUMBING_LINE_BYTES` so a hostile repo emitting a
    // multi-gigabyte single line (no `\n`) cannot exhaust memory, a real
    // commit-id line is ~40-64 bytes, and an over-cap line is a loud truncation
    // error, not a silent OOM (the std `BufRead::lines()` this replaced buffered
    // the whole line unbounded).
    log_reader: std::io::BufReader<ChildStdout>,
    log_line_buf: Vec<u8>,
    log_done: bool,
    unreachable_loaded: bool,
    unreachable_truncated: bool,
    unreachable_commits: VecDeque<gix::ObjectId>,
    unreachable_blobs: VecDeque<gix::ObjectId>,
    unreachable_trees: VecDeque<gix::ObjectId>,
    unreachable_tags: VecDeque<gix::ObjectId>,
    limits: crate::SourceLimits,
}

impl GitCommitEnumerator {
    fn new(
        repo_arg: String,
        max_commits: Option<usize>,
        limits: crate::SourceLimits,
    ) -> Result<Self, SourceError> {
        // Get commit hashes from refs plus reflogs. `--all` alone misses deleted
        // branch reflog commits on current Git, and it also misses refs/stash on
        // some versions, so stash is added explicitly when present.
        let mut log_cmd = super::git_command()?;
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
        let mut log_child = super::spawn_git_child(log_cmd)?;
        let log_stdout = log_child
            .take_stdout()
            .ok_or_else(|| SourceError::Io(std::io::Error::other("missing log stdout")))?;
        let log_reader = std::io::BufReader::new(log_stdout);

        Ok(Self {
            repo_arg,
            max_commits,
            log_child,
            log_reader,
            log_line_buf: Vec::new(),
            log_done: false,
            unreachable_loaded: false,
            unreachable_truncated: false,
            unreachable_commits: VecDeque::new(),
            unreachable_blobs: VecDeque::new(),
            unreachable_trees: VecDeque::new(),
            unreachable_tags: VecDeque::new(),
            limits,
        })
    }

    fn next_id(&mut self, seen_commit_count: usize) -> Result<Option<gix::ObjectId>, SourceError> {
        loop {
            if let Some(id) = self.unreachable_commits.pop_front() {
                return Ok(Some(id));
            }
            if !self.log_done {
                let record = super::read_capped_line(
                    &mut self.log_reader,
                    &mut self.log_line_buf,
                    super::GIT_PLUMBING_LINE_BYTES,
                )
                .map_err(SourceError::Io)?;
                if record.consumed == 0 {
                    self.log_done = true;
                    super::wait_for_git_child(
                        &mut self.log_child,
                        "git log",
                        "enumerating git commits",
                    )?;
                    continue;
                }
                // A commit-id line over the plumbing cap is corrupt/hostile git
                // output (a real object-id line is tiny), fail LOUDLY, never
                // silently scan a truncated id (Law 10), matching the sibling
                // tag-message and fsck plumbing readers.
                if record.content > super::GIT_PLUMBING_LINE_BYTES {
                    return Err(super::git_output_line_truncated_error(
                        "git log source",
                        "commit id line",
                        super::GIT_PLUMBING_LINE_BYTES,
                        record.content,
                    ));
                }
                let line = String::from_utf8_lossy(&self.log_line_buf);
                let line = line.trim_end_matches('\n').trim_end_matches('\r');
                if let Some(id) = parse_git_object_id_line(line, "commit") {
                    return Ok(Some(id));
                }
                continue;
            }
            if !self.unreachable_loaded {
                self.unreachable_loaded = true;
                let remaining = self
                    .max_commits
                    .map(|limit| limit.saturating_sub(seen_commit_count));
                let unreachable =
                    collect_unreachable_objects(&self.repo_arg, remaining, self.limits)?;
                self.unreachable_truncated = unreachable.truncated;
                self.unreachable_commits = unreachable.commits;
                self.unreachable_blobs = unreachable.blobs;
                self.unreachable_trees = unreachable.trees;
                self.unreachable_tags = unreachable.tags;
                continue;
            }
            return Ok(None);
        }
    }

    fn take_unreachable_non_commit_objects(&mut self) -> UnreachableGitObjects {
        UnreachableGitObjects {
            commits: VecDeque::new(),
            blobs: std::mem::take(&mut self.unreachable_blobs),
            trees: std::mem::take(&mut self.unreachable_trees),
            tags: std::mem::take(&mut self.unreachable_tags),
            tree_blob_oids: HashSet::new(),
            truncated: false,
        }
    }

    fn take_unreachable_truncation_error(&mut self) -> Option<SourceError> {
        if !self.unreachable_truncated {
            return None;
        }
        self.unreachable_truncated = false;
        let mut reported = false;
        super::record_git_cap_once(
            super::GitHistoryCap::Chunks {
                count: self.limits.git_chunk_count,
                cap: self.limits.git_chunk_count,
            },
            &mut reported,
            "git unreachable object enumeration",
            "remaining unreachable objects",
        )
    }
}

fn stream_git_blobs(
    repo_path: &Path,
    max_commits: Option<usize>,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
) -> Result<impl Iterator<Item = Result<Chunk, SourceError>>, SourceError> {
    let repo_arg = super::validate_repo_path(repo_path)?;
    let mut commit_ids = GitCommitEnumerator::new(repo_arg.clone(), max_commits, limits)?;

    // Open the gix repo ONCE and reuse it for every commit. The previous
    // version called `gix::open(&repo_owned)` per-commit which on a 10k-commit
    // repo opened the repo 10k times - fd churn + IO amplification.
    let repo_owned = PathBuf::from(&repo_arg);
    let repo_handle = gix::open(&repo_owned)
        .map_err(|e| SourceError::Io(std::io::Error::other(format!("gix open: {e}"))))?;
    // A shallow clone cannot answer "what did history contain": say so before
    // emitting a single chunk, so a truncated history can never read as clean.
    super::record_shallow_history_gap(&repo_handle, "git blob source (--git-blobs)");
    let mut reachable_tags = collect_reachable_tag_messages(&repo_arg)?;
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
    let head_blob_paths = collect_head_blob_path_set(&repo_handle)?;
    let mut current_tree_blobs: VecDeque<Chunk> = VecDeque::new();
    let mut pending_errors: VecDeque<SourceError> = VecDeque::new();
    let mut seen_blob_paths: HashSet<GitBlobPathKey> = HashSet::new();
    let mut seen_commits: HashSet<gix::ObjectId> = HashSet::new();
    // Tree object ids already walked cleanly this scan; identical subtrees
    // recur across commits (most of a tree is untouched by any one commit),
    // so memoizing them prunes nearly all repeated descents.
    let mut walked_trees: HashSet<gix::ObjectId> = HashSet::new();
    // Every ref tip under refs/ plus HEAD must be fully enumerated once so
    // `--max-commits` still covers untouched blobs on each tip tree
    // (including custom ref namespaces and detached CI checkouts). Non-tip commits
    // use parent-tree diffs for O(changed) work.
    let ref_tip_oids = collect_ref_tip_oids(&repo_arg)?;
    let mut unreachable_objects: Option<UnreachableGitObjects> = None;
    let mut pending_blob_decode: Option<PendingGitBlobDecode> = None;
    let mut total_bytes = 0usize;
    let mut chunk_count = 0usize;
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

            if let Some(pending) = pending_blob_decode.as_mut() {
                let chunk_decoder = GitBlobChunkDecoder {
                    repo: &repo_handle,
                    repo_path: &repo_owned,
                    head_blob_paths: &head_blob_paths,
                    limits,
                };
                let PendingGitBlobDecode {
                    blob_metadata,
                    provenance,
                } = pending;
                current_tree_blobs.extend(chunk_decoder.decode_next_batch(
                    blob_metadata,
                    provenance.borrowed(),
                    &mut total_bytes,
                    &mut chunk_count,
                    &mut pending_errors,
                ));
                let exhausted = blob_metadata.as_slice().is_empty()
                    || super::git_history_cap_status(total_bytes, chunk_count, limits).is_some();
                if exhausted {
                    pending_blob_decode = None;
                }
                if let Some(chunk) = current_tree_blobs.pop_front() {
                    return Some(Ok(chunk));
                }
                if pending_blob_decode.is_some() {
                    continue;
                }
            }

            if let Some(error) = pending_errors.pop_front() {
                return Some(Err(error));
            }

            if let Some(cap) = super::git_history_cap_status(total_bytes, chunk_count, limits) {
                let error = super::record_git_history_cap_once(cap, &mut aggregate_cap_reported);
                done = true;
                return error.map(Err);
            }

            if unreachable_objects.is_none() {
                let id = match commit_ids.next_id(seen_commits.len()) {
                    Ok(Some(id)) => id,
                    Ok(None) => {
                        if let Some(error) = commit_ids.take_unreachable_truncation_error() {
                            pending_errors.push_back(error);
                        }
                        if let Some(chunk) = decode_next_tag_message(
                            &repo_handle,
                            &mut reachable_tags,
                            limits,
                            &mut total_bytes,
                            &mut chunk_count,
                            &mut pending_errors,
                        ) {
                            return Some(Ok(chunk));
                        }
                        unreachable_objects =
                            Some(commit_ids.take_unreachable_non_commit_objects());
                        continue;
                    }
                    Err(error) => {
                        done = true;
                        return Some(Err(error));
                    }
                };

                // Cache visited Git commit OIDs in a fast set to avoid traversing duplicate merge commits (KH-56)
                if !seen_commits.insert(id) {
                    continue;
                }

                let force_full_walk = ref_tip_oids.contains(&id);
                let commit_blobs = match load_commit_blob_set(
                    &repo_handle,
                    id,
                    &mut seen_blob_paths,
                    &mut walked_trees,
                    respect_default_excludes,
                    force_full_walk,
                ) {
                    Ok(Some(commit_blobs)) => commit_blobs,
                    Ok(None) => continue,
                    Err(error) => {
                        done = true;
                        return Some(Err(error));
                    }
                };
                let GitCommitBlobSet {
                    commit_id,
                    author,
                    blob_metadata,
                    errors,
                } = commit_blobs;
                pending_errors.extend(errors);

                if !blob_metadata.is_empty() {
                    pending_blob_decode = Some(PendingGitBlobDecode {
                        blob_metadata: blob_metadata.into_iter(),
                        provenance: PendingGitBlobProvenance::Commit { commit_id, author },
                    });
                    continue;
                }
            } else if let Some(objects) = unreachable_objects.as_mut() {
                if let Some(chunk) = decode_next_unreachable_tag_message(
                    &repo_handle,
                    &mut objects.tags,
                    limits,
                    &mut total_bytes,
                    &mut chunk_count,
                    &mut pending_errors,
                ) {
                    return Some(Ok(chunk));
                }

                let blob_metadata = collect_unreachable_non_commit_blob_metadata(
                    &repo_handle,
                    objects,
                    &mut seen_blob_paths,
                    &mut walked_trees,
                    respect_default_excludes,
                );
                pending_errors.extend(blob_metadata.errors);
                if blob_metadata.metadata.is_empty() {
                    if !pending_errors.is_empty() {
                        continue;
                    }
                    done = true;
                    return None;
                }

                pending_blob_decode = Some(PendingGitBlobDecode {
                    blob_metadata: blob_metadata.metadata.into_iter(),
                    provenance: PendingGitBlobProvenance::Unreachable,
                });
                continue;
            }
        }
    }))
}

fn load_commit_blob_set(
    repo: &gix::Repository,
    id: gix::ObjectId,
    seen_blob_paths: &mut HashSet<GitBlobPathKey>,
    walked_trees: &mut HashSet<gix::ObjectId>,
    respect_default_excludes: bool,
    force_full_walk: bool,
) -> Result<Option<GitCommitBlobSet>, SourceError> {
    let commit_id = id.to_string();
    // Law 10: `git log` already enumerated this commit, so a gix failure to
    // load its object / commit / tree means a commit's blobs are NOT
    // scanned (corrupt object, partial clone missing the tree). Count each
    // as unreadable + warn so the dropped commit is operator-visible rather
    // than a silent `continue` that reads as full history coverage.
    let _tree_walk = crate::profile::walk_span();
    let obj = match repo.find_object(id) {
        Ok(o) => o,
        Err(error) => {
            tracing::warn!(%error, commit = %commit_id, "git commit object unreadable; its blobs were NOT scanned");
            record_git_object_unreadable();
            return Ok(Some(GitCommitBlobSet {
                commit_id: commit_id.clone(),
                author: "unknown".to_string(),
                blob_metadata: Vec::new(),
                errors: vec![git_unscanned_object_error(format!(
                    "git commit object {commit_id} unreadable ({error}); commit blobs were not scanned"
                ))],
            }));
        }
    };
    let commit = match obj.try_into_commit() {
        Ok(c) => c,
        Err(error) => {
            tracing::warn!(%error, commit = %commit_id, "git object is not a commit; its blobs were NOT scanned");
            record_git_object_unreadable();
            return Ok(Some(GitCommitBlobSet {
                commit_id: commit_id.clone(),
                author: "unknown".to_string(),
                blob_metadata: Vec::new(),
                errors: vec![git_unscanned_object_error(format!(
                    "git object {commit_id} is not a commit ({error}); commit blobs were not scanned"
                ))],
            }));
        }
    };
    let author = commit_author_name(&commit, &commit_id)?;
    // Early-skip: a root tree already walked cleanly this scan (an identical
    // tree reached through another commit/ref) contributes no new (oid, path)
    // blob identities, so skip the tree read and the whole walk. `tree_id`
    // decodes only the commit header, so the skip happens before any blob or
    // tree object load.
    // LAW10: recall-safe in the loud direction. An unreadable commit header skips the
    // memo probe only, so the walk falls through to `commit.tree()` below, which counts
    // and surfaces the unreadable object. The fallback can add work, never drop coverage.
    if let Ok(root_tree_id) = commit.tree_id() {
        if walked_trees.contains(&root_tree_id.detach()) {
            return Ok(Some(GitCommitBlobSet {
                commit_id,
                author,
                blob_metadata: Vec::new(),
                errors: Vec::new(),
            }));
        }
    }
    let tree = match commit.tree() {
        Ok(t) => t,
        Err(error) => {
            tracing::warn!(%error, commit = %commit_id, "git commit tree unreadable; its blobs were NOT scanned");
            record_git_object_unreadable();
            return Ok(Some(GitCommitBlobSet {
                commit_id: commit_id.clone(),
                author,
                blob_metadata: Vec::new(),
                errors: vec![git_unscanned_object_error(format!(
                    "git commit tree for {commit_id} unreadable ({error}); commit blobs were not scanned"
                ))],
            }));
        }
    };

    let mut blob_metadata = Vec::new();
    let mut errors = Vec::new();
    // Prefer parent-tree diffs over full tree rewalks. Flat histories (one new
    // root entry per commit) otherwise re-scan O(n) entries per commit → O(n²)
    // object-header traffic. Diffs emit only added/changed paths; deletions'
    // old blob sides are kept so newest-first `git log` order still recalls
    // credentials that were removed later. The scan tip, root commits, and
    // unreadable parents fall back to a full walk (recall-safe under
    // `--max-commits`: untouched tip blobs must still be scanned).
    let parent_ids: Vec<gix::ObjectId> = commit.parent_ids().map(|id| id.detach()).collect();
    // Root-tree memoization is only valid after a FULL enumeration of that tree.
    // Parent-tree diffs emit only changed sides; marking the root walked afterwards
    // would let a later commit that reuses the same tree early-skip and drop blobs
    // that were never collected on the first visit (e.g. revert-to-earlier-tree).
    let root_fully_enumerated = if force_full_walk || parent_ids.is_empty() {
        collect_tree_blobs_metadata(
            repo,
            &tree,
            seen_blob_paths,
            walked_trees,
            None,
            &mut blob_metadata,
            b"",
            &mut errors,
            respect_default_excludes,
        );
        true
    } else {
        collect_commit_blobs_via_parent_diffs(
            repo,
            &tree,
            &parent_ids,
            seen_blob_paths,
            walked_trees,
            &mut blob_metadata,
            &mut errors,
            respect_default_excludes,
        )
    };
    // Memoize the root tree only after a full walk with no error, so a corrupt
    // subtree keeps re-reporting (and re-attempting) on later commits.
    if root_fully_enumerated && errors.is_empty() {
        // LAW10: failing to read the tree id only skips memoization, so later commits
        // re-walk this tree instead of trusting a memo. Recall-safe by construction.
        if let Ok(root_tree_id) = commit.tree_id() {
            walked_trees.insert(root_tree_id.detach());
        }
    }

    Ok(Some(GitCommitBlobSet {
        commit_id,
        author,
        blob_metadata,
        errors,
    }))
}

struct GitBlobChunkDecoder<'a> {
    repo: &'a gix::Repository,
    repo_path: &'a Path,
    head_blob_paths: &'a HashSet<GitBlobPathKey>,
    limits: crate::SourceLimits,
}

impl GitBlobChunkDecoder<'_> {
    fn decode_next_batch(
        &self,
        blob_metadata: &mut std::vec::IntoIter<(gix::ObjectId, Vec<u8>)>,
        provenance: GitBlobProvenance<'_>,
        total_bytes: &mut usize,
        chunk_count: &mut usize,
        pending_errors: &mut VecDeque<SourceError>,
    ) -> VecDeque<Chunk> {
        let mut chunks = VecDeque::new();
        if super::git_history_cap_status(*total_bytes, *chunk_count, self.limits).is_some() {
            return chunks;
        }

        let batch = next_git_blob_batch(self.repo, blob_metadata, self.limits);
        if batch.is_empty() {
            return chunks;
        }

        // Blob payload reads (one decode per UNIQUE blob oid in this batch;
        // duplicate (oid, path) entries fan out the shared decoded text).
        let _blob_read = crate::profile::read_span();
        let mut unique_candidates: Vec<GitBlobCandidate> = Vec::new();
        let mut oid_slots: HashMap<gix::ObjectId, usize> = HashMap::new();
        for item in &batch {
            if let GitBlobBatchItem::Candidate(candidate) = item {
                if !oid_slots.contains_key(&candidate.oid) {
                    oid_slots.insert(candidate.oid, unique_candidates.len());
                    unique_candidates.push(candidate.clone());
                }
            }
        }
        let outcomes = decode_git_blob_candidates(self.repo, self.repo_path, unique_candidates);

        for item in batch {
            if super::git_history_cap_status(*total_bytes, *chunk_count, self.limits).is_some() {
                break;
            }

            let decoded_blob = match item {
                GitBlobBatchItem::Skip(skip) => {
                    record_git_blob_skip(skip, pending_errors);
                    continue;
                }
                GitBlobBatchItem::Candidate(candidate) => {
                    let slot = oid_slots[&candidate.oid];
                    match &outcomes[slot] {
                        Some(Ok(shared)) => DecodedGitBlob {
                            oid: candidate.oid,
                            filepath: candidate.filepath,
                            size_bytes: shared.size_bytes,
                            file_text: shared.file_text.clone(),
                        },
                        Some(Err(kind)) => {
                            record_git_blob_skip(
                                kind.with_identity(candidate.oid, candidate.filepath),
                                pending_errors,
                            );
                            continue;
                        }
                        None => {
                            tracing::warn!(
                                %candidate.oid,
                                "git blob decode batch lost an outcome; blob NOT scanned"
                            );
                            record_git_object_unreadable();
                            pending_errors.push_back(git_unscanned_object_error(format!(
                                "git blob {} at {} lost its decode outcome; blob was not scanned",
                                candidate.oid,
                                git_blob_path_display(&candidate.filepath)
                            )));
                            continue;
                        }
                    }
                }
            };

            let chunk = self.chunk_from_decoded_blob(decoded_blob, provenance);
            *total_bytes = total_bytes.saturating_add(chunk.data.len());
            *chunk_count += 1;
            chunks.push_back(chunk);
        }

        record_buffered_git_blob_chunks(chunks.len());
        chunks
    }

    fn chunk_from_decoded_blob(
        &self,
        decoded_blob: DecodedGitBlob,
        provenance: GitBlobProvenance<'_>,
    ) -> Chunk {
        let in_head = self
            .head_blob_paths
            .contains(&(decoded_blob.oid.to_owned(), decoded_blob.filepath.clone()));
        let path = String::from_utf8_lossy(&decoded_blob.filepath).to_string();
        let (source_type, commit, author) = match provenance {
            GitBlobProvenance::Commit { commit_id, author } => (
                if in_head { "git/head" } else { "git/history" },
                Some(commit_id.to_owned()),
                Some(author.to_owned()),
            ),
            GitBlobProvenance::Unreachable => ("git/unreachable", None, None),
        };
        Chunk {
            data: decoded_blob.file_text.into(),
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: source_type.into(),
                path: Some(path.into()),
                commit: commit.map(Into::into),
                author: author.map(Into::into),
                date: None,
                mtime_ns: None,
                size_bytes: Some(decoded_blob.size_bytes),
                decoded_span: None,
            },
        }
    }
}

#[derive(Clone, Copy)]
enum GitBlobProvenance<'a> {
    Commit { commit_id: &'a str, author: &'a str },
    Unreachable,
}

fn next_git_blob_batch(
    repo: &gix::Repository,
    blob_metadata: &mut std::vec::IntoIter<(gix::ObjectId, Vec<u8>)>,
    limits: crate::SourceLimits,
) -> Vec<GitBlobBatchItem> {
    let mut batch = Vec::new();
    let mut batch_bytes = 0u64;
    let mut batch_items = 0usize;
    // One header read per unique blob oid per batch: duplicate (oid, path)
    // entries resolve kind/size from the memo instead of re-opening the
    // object, while still producing their own per-path skip entries.
    let mut header_memo: HashMap<gix::ObjectId, Result<(Kind, u64), String>> = HashMap::new();

    while batch_items < GIT_PARALLEL_BLOB_BATCH_ITEMS && batch_bytes < GIT_PARALLEL_BLOB_BATCH_BYTES
    {
        let Some((oid, filepath)) = blob_metadata.next() else {
            break;
        };
        batch_items += 1;

        let header = match header_memo.entry(oid).or_insert_with(|| {
            repo.find_header(oid)
                .map(|h| (h.kind(), h.size()))
                .map_err(|e| e.to_string())
        }) {
            Ok(header) => *header,
            Err(error) => {
                batch.push(GitBlobBatchItem::Skip(GitBlobSkip::HeaderUnreadable {
                    oid,
                    filepath,
                    error: error.clone(),
                }));
                continue;
            }
        };

        if header.0 != Kind::Blob {
            batch.push(GitBlobBatchItem::Skip(GitBlobSkip::NonBlob {
                oid,
                filepath,
                kind: format!("{:?}", header.0),
            }));
            continue;
        }

        let size_bytes = header.1;
        if size_bytes > limits.git_blob_bytes {
            batch.push(GitBlobBatchItem::Skip(GitBlobSkip::OverMaxSize {
                oid,
                filepath,
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

fn decode_git_blob_candidates(
    repo: &gix::Repository,
    _repo_path: &Path,
    candidates: Vec<GitBlobCandidate>,
) -> Vec<Option<Result<SharedDecodedBlob, GitBlobOidSkipKind>>> {
    // Always decode on the already-open repository handle. A prior parallel
    // path reopened the repo per rayon worker (`gix::open`) and stalled at
    // near-idle CPU under pack/lock contention on busy hosts, including tip
    // full-walk batches. Serial decode on the shared handle stays recall-safe
    // and avoids that hang class.
    candidates
        .into_iter()
        .map(|candidate| Some(decode_one_git_blob(repo, candidate)))
        .collect()
}

fn decode_one_git_blob(
    repo: &gix::Repository,
    candidate: GitBlobCandidate,
) -> Result<SharedDecodedBlob, GitBlobOidSkipKind> {
    let obj = repo
        .find_object(candidate.oid)
        .map_err(|error| GitBlobOidSkipKind::ObjectUnreadable(error.to_string()))?;
    let Some(file_text) = decode_git_blob(&obj.data) else {
        return Err(GitBlobOidSkipKind::Binary);
    };
    Ok(SharedDecodedBlob {
        size_bytes: candidate.size_bytes,
        file_text: file_text.into(),
    })
}

fn record_git_blob_skip(skip: GitBlobSkip, pending_errors: &mut VecDeque<SourceError>) {
    match skip {
        GitBlobSkip::HeaderUnreadable {
            oid,
            filepath,
            error,
        } => {
            // Law 10: the blob is referenced by the tree but its object header
            // could not be read. It is not scanned, so count it as unreadable.
            tracing::warn!(
                %error, %oid,
                "git blob header unreadable (corrupt/missing object); blob NOT scanned"
            );
            record_git_object_unreadable();
            pending_errors.push_back(git_unscanned_object_error(format!(
                "git blob {oid} at {} header unreadable ({error}); blob was not scanned",
                git_blob_path_display(&filepath)
            )));
        }
        GitBlobSkip::NonBlob {
            oid,
            filepath,
            kind,
        } => {
            tracing::warn!(
                %oid,
                kind,
                "git tree entry resolved to a non-blob object; blob NOT scanned"
            );
            record_git_object_unreadable();
            pending_errors.push_back(git_unscanned_object_error(format!(
                "git blob {oid} at {} resolved to non-blob object kind {kind}; blob was not scanned",
                git_blob_path_display(&filepath)
            )));
        }
        GitBlobSkip::OverMaxSize {
            oid,
            filepath,
            size,
            cap,
        } => {
            tracing::warn!(
                %oid,
                size,
                cap,
                "git blob exceeds the per-blob size cap; NOT scanned"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            pending_errors.push_back(git_unscanned_object_error(format!(
                "git blob {oid} at {} exceeds per-blob size cap ({size} bytes > {cap} bytes); blob was not scanned",
                git_blob_path_display(&filepath)
            )));
        }
        GitBlobSkip::ObjectUnreadable {
            oid,
            filepath,
            error,
        } => {
            tracing::warn!(
                %error, %oid,
                "git blob object unreadable (corrupt/missing object); blob NOT scanned"
            );
            record_git_object_unreadable();
            pending_errors.push_back(git_unscanned_object_error(format!(
                "git blob {oid} at {} object unreadable ({error}); blob was not scanned",
                git_blob_path_display(&filepath)
            )));
        }
        GitBlobSkip::Binary { oid, filepath } => {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
            pending_errors.push_back(git_unscanned_object_error(format!(
                "git blob {oid} at {} is binary and was not decoded as text; blob was not scanned",
                git_blob_path_display(&filepath)
            )));
        }
    }
}

fn git_blob_path_display(filepath: &[u8]) -> String {
    String::from_utf8_lossy(filepath).into_owned()
}

/// Decode a git blob into scannable text with the same recall-preserving
/// contract as the filesystem source.
fn decode_git_blob(data: &[u8]) -> Option<String> {
    crate::filesystem::decode_text_file(data)
}

fn git_ref_exists(repo_arg: &str, ref_name: &str) -> Result<bool, SourceError> {
    let output = super::git_command()?
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

#[derive(Clone, Copy)]
enum FsckUnreachableObjectKind {
    Commit,
    Blob,
    Tree,
    Tag,
}

const FSCK_UNREACHABLE_OBJECT_PREFIXES: &[(&str, FsckUnreachableObjectKind)] = &[
    ("unreachable commit ", FsckUnreachableObjectKind::Commit),
    ("unreachable blob ", FsckUnreachableObjectKind::Blob),
    ("unreachable tree ", FsckUnreachableObjectKind::Tree),
    ("unreachable tag ", FsckUnreachableObjectKind::Tag),
    ("dangling commit ", FsckUnreachableObjectKind::Commit),
    ("dangling blob ", FsckUnreachableObjectKind::Blob),
    ("dangling tree ", FsckUnreachableObjectKind::Tree),
    ("dangling tag ", FsckUnreachableObjectKind::Tag),
];

fn parse_fsck_unreachable_object_line(line: &str) -> Option<(FsckUnreachableObjectKind, &str)> {
    FSCK_UNREACHABLE_OBJECT_PREFIXES
        .iter()
        .find_map(|(prefix, kind)| {
            line.strip_prefix(prefix)
                .map(|object_id| (*kind, object_id))
        })
}

fn collect_unreachable_objects(
    repo_arg: &str,
    remaining_commits: Option<usize>,
    limits: crate::SourceLimits,
) -> Result<UnreachableGitObjects, SourceError> {
    let mut command = super::git_command()?;
    command.args([
        "-C",
        repo_arg,
        "fsck",
        "--unreachable",
        "--no-reflogs",
        "--no-progress",
    ]);
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = super::spawn_git_child(command)?;
    let stdout = child
        .take_stdout()
        .ok_or_else(|| SourceError::Io(std::io::Error::other("missing fsck stdout")))?;
    let mut reader = std::io::BufReader::new(stdout);
    let mut out = UnreachableGitObjects::default();
    let mut line_buf = Vec::new();
    while super::read_capped_line(&mut reader, &mut line_buf, super::GIT_PLUMBING_LINE_BYTES)
        .map_err(SourceError::Io)?
        .consumed
        > 0
    {
        let line = String::from_utf8_lossy(&line_buf);
        let line = line.trim_end_matches('\n').trim_end_matches('\r');
        let Some((kind, object_id)) = parse_fsck_unreachable_object_line(line) else {
            continue;
        };
        match kind {
            FsckUnreachableObjectKind::Commit => {
                if remaining_commits.is_some_and(|limit| out.commits.len() >= limit) {
                    continue;
                }
                if !out.has_collection_capacity(limits) {
                    continue;
                }
                let Some(id) = parse_git_object_id_line(object_id, "commit") else {
                    continue;
                };
                out.commits.push_back(id);
            }
            FsckUnreachableObjectKind::Blob => {
                if !out.has_collection_capacity(limits) {
                    continue;
                }
                let Some(id) = parse_git_object_id_line(object_id, "blob") else {
                    continue;
                };
                out.blobs.push_back(id);
            }
            FsckUnreachableObjectKind::Tree => {
                if !out.has_collection_capacity(limits) {
                    continue;
                }
                let Some(id) = parse_git_object_id_line(object_id, "tree") else {
                    continue;
                };
                out.trees.push_back(id);
            }
            FsckUnreachableObjectKind::Tag => {
                if !out.has_collection_capacity(limits) {
                    continue;
                }
                let Some(id) = parse_git_object_id_line(object_id, "tag") else {
                    continue;
                };
                out.tags.push_back(id);
            }
        }
    }
    super::wait_for_git_child(&mut child, "git fsck", "enumerating unreachable objects")?;
    Ok(out)
}

fn collect_unreachable_non_commit_blob_metadata(
    repo: &gix::Repository,
    objects: &mut UnreachableGitObjects,
    seen_blob_paths: &mut HashSet<GitBlobPathKey>,
    walked_trees: &mut HashSet<gix::ObjectId>,
    respect_default_excludes: bool,
) -> GitBlobMetadataBatch {
    let mut batch = GitBlobMetadataBatch::default();
    while batch.metadata.len() < GIT_PARALLEL_BLOB_BATCH_ITEMS {
        let Some(id) = objects.trees.pop_front() else {
            break;
        };
        collect_unreachable_tree_blob_metadata(
            repo,
            id,
            seen_blob_paths,
            walked_trees,
            &mut objects.tree_blob_oids,
            &mut batch.metadata,
            &mut batch.errors,
            respect_default_excludes,
        );
    }
    if !objects.trees.is_empty() {
        return batch;
    }
    while batch.metadata.len() < GIT_PARALLEL_BLOB_BATCH_ITEMS {
        let Some(id) = objects.blobs.pop_front() else {
            break;
        };
        if objects.tree_blob_oids.contains(&id) {
            continue;
        }
        batch
            .metadata
            .push((id, format!(".git/unreachable/{id}").into_bytes()));
    }
    batch
}

fn collect_unreachable_tree_blob_metadata(
    repo: &gix::Repository,
    tree_id: gix::ObjectId,
    seen_blob_paths: &mut HashSet<GitBlobPathKey>,
    walked_trees: &mut HashSet<gix::ObjectId>,
    tree_blob_oids: &mut HashSet<gix::ObjectId>,
    blob_metadata: &mut Vec<(gix::ObjectId, Vec<u8>)>,
    errors: &mut Vec<SourceError>,
    respect_default_excludes: bool,
) {
    let obj = match repo.find_object(tree_id) {
        Ok(obj) => obj,
        Err(error) => {
            tracing::warn!(
                %error,
                tree = %tree_id,
                "unreachable git tree object unreadable; its blobs were NOT scanned"
            );
            record_git_object_unreadable();
            errors.push(git_unscanned_object_error(format!(
                "unreachable git tree object {tree_id} unreadable ({error}); tree blobs were not scanned"
            )));
            return;
        }
    };
    let tree = match obj.try_into_tree() {
        Ok(tree) => tree,
        Err(error) => {
            tracing::warn!(
                %error,
                tree = %tree_id,
                "unreachable git object is not a tree; its blobs were NOT scanned"
            );
            record_git_object_unreadable();
            errors.push(git_unscanned_object_error(format!(
                "unreachable git object {tree_id} is not a tree ({error}); tree blobs were not scanned"
            )));
            return;
        }
    };

    let before = blob_metadata.len();
    collect_tree_blobs_metadata(
        repo,
        &tree,
        seen_blob_paths,
        walked_trees,
        Some(tree_blob_oids),
        blob_metadata,
        b"",
        errors,
        respect_default_excludes,
    );
    tree_blob_oids.extend(
        blob_metadata[before..]
            .iter()
            .map(|(oid, _)| oid.to_owned()),
    );
    let prefix = format!(".git/unreachable/{tree_id}/").into_bytes();
    for (_, path) in &mut blob_metadata[before..] {
        let mut synthetic = Vec::with_capacity(prefix.len() + path.len());
        synthetic.extend_from_slice(&prefix);
        synthetic.extend_from_slice(path);
        *path = synthetic;
    }
}

fn commit_author_name(commit: &gix::Commit<'_>, commit_id: &str) -> Result<String, SourceError> {
    let author = commit.author().map_err(|error| {
        SourceError::Git(format!(
            "failed to read git commit author metadata for {commit_id}: {error}"
        ))
    })?;
    let name = String::from_utf8_lossy(author.name.as_ref())
        .trim()
        .to_string();
    if name.is_empty() {
        Ok("unknown".to_string())
    } else {
        Ok(name)
    }
}

/// Returns `true` when this commit fell back to a full tree walk (so the root
/// may be memoized), and `false` when only parent-tree diff sides were collected.
fn collect_commit_blobs_via_parent_diffs(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
    parent_ids: &[gix::ObjectId],
    seen_blob_paths: &mut HashSet<GitBlobPathKey>,
    walked_trees: &mut HashSet<gix::ObjectId>,
    blob_metadata: &mut Vec<(gix::ObjectId, Vec<u8>)>,
    errors: &mut Vec<SourceError>,
    respect_default_excludes: bool,
) -> bool {
    let mut diff_state = gix::diff::tree::State::default();
    let mut records = Vec::new();
    for parent_id in parent_ids {
        let Some(parent_tree) = load_commit_tree_for_diff(repo, *parent_id) else {
            // Unreadable parent: keep already-collected deletion/previous sides
            // from earlier parents, then full-walk the current tree. The parent
            // commit's own visit already recorded the coverage gap.
            absorb_tree_diff_blob_records(
                std::mem::take(&mut records),
                seen_blob_paths,
                blob_metadata,
                errors,
                respect_default_excludes,
            );
            collect_tree_blobs_metadata(
                repo,
                tree,
                seen_blob_paths,
                walked_trees,
                None,
                blob_metadata,
                b"",
                errors,
                respect_default_excludes,
            );
            return true;
        };
        if parent_tree.id == tree.id {
            continue;
        }
        let mut recorder = gix::diff::tree::Recorder::default()
            .track_location(Some(gix::diff::tree::recorder::Location::Path));
        if let Err(error) = gix::diff::tree(
            gix::objs::TreeRefIter::from_bytes(&parent_tree.data),
            gix::objs::TreeRefIter::from_bytes(&tree.data),
            &mut diff_state,
            &repo.objects,
            &mut recorder,
        ) {
            tracing::warn!(
                %error,
                parent = %parent_id,
                "git parent-tree diff failed; falling back to a full tree walk for recall"
            );
            absorb_tree_diff_blob_records(
                std::mem::take(&mut records),
                seen_blob_paths,
                blob_metadata,
                errors,
                respect_default_excludes,
            );
            collect_tree_blobs_metadata(
                repo,
                tree,
                seen_blob_paths,
                walked_trees,
                None,
                blob_metadata,
                b"",
                errors,
                respect_default_excludes,
            );
            return true;
        }
        records.extend(recorder.records);
    }
    absorb_tree_diff_blob_records(
        records,
        seen_blob_paths,
        blob_metadata,
        errors,
        respect_default_excludes,
    );
    false
}

fn load_commit_tree_for_diff<'a>(
    repo: &'a gix::Repository,
    parent_id: gix::ObjectId,
) -> Option<gix::Tree<'a>> {
    let obj = match repo.find_object(parent_id) {
        Ok(obj) => obj,
        Err(error) => {
            tracing::warn!(
                %error,
                parent = %parent_id,
                "git parent commit object unreadable during tree diff"
            );
            return None;
        }
    };
    let commit = match obj.try_into_commit() {
        Ok(commit) => commit,
        Err(error) => {
            tracing::warn!(
                %error,
                parent = %parent_id,
                "git parent object is not a commit during tree diff"
            );
            return None;
        }
    };
    match commit.tree() {
        Ok(tree) => Some(tree),
        Err(error) => {
            tracing::warn!(
                %error,
                parent = %parent_id,
                "git parent commit tree unreadable during tree diff"
            );
            None
        }
    }
}

fn absorb_tree_diff_blob_records(
    records: Vec<gix::diff::tree::recorder::Change>,
    seen_blob_paths: &mut HashSet<GitBlobPathKey>,
    blob_metadata: &mut Vec<(gix::ObjectId, Vec<u8>)>,
    errors: &mut Vec<SourceError>,
    respect_default_excludes: bool,
) {
    for change in records {
        match change {
            gix::diff::tree::recorder::Change::Addition {
                entry_mode,
                oid,
                path,
                ..
            } => {
                consider_diff_blob_path(
                    oid,
                    path.as_ref(),
                    entry_mode,
                    seen_blob_paths,
                    blob_metadata,
                    errors,
                    respect_default_excludes,
                );
            }
            gix::diff::tree::recorder::Change::Deletion {
                entry_mode,
                oid,
                path,
                ..
            } => {
                // Newest-first history: a deletion is often the first time this
                // scan observes a historical blob that no longer exists in
                // newer trees. Keep the deleted blob side for recall.
                consider_diff_blob_path(
                    oid,
                    path.as_ref(),
                    entry_mode,
                    seen_blob_paths,
                    blob_metadata,
                    errors,
                    respect_default_excludes,
                );
            }
            gix::diff::tree::recorder::Change::Modification {
                previous_entry_mode,
                previous_oid,
                entry_mode,
                oid,
                path,
            } => {
                consider_diff_blob_path(
                    oid,
                    path.as_ref(),
                    entry_mode,
                    seen_blob_paths,
                    blob_metadata,
                    errors,
                    respect_default_excludes,
                );
                consider_diff_blob_path(
                    previous_oid,
                    path.as_ref(),
                    previous_entry_mode,
                    seen_blob_paths,
                    blob_metadata,
                    errors,
                    respect_default_excludes,
                );
            }
        }
    }
}

fn consider_diff_blob_path(
    oid: gix::ObjectId,
    path: &[u8],
    entry_mode: gix::objs::tree::EntryMode,
    seen_blob_paths: &mut HashSet<GitBlobPathKey>,
    blob_metadata: &mut Vec<(gix::ObjectId, Vec<u8>)>,
    errors: &mut Vec<SourceError>,
    respect_default_excludes: bool,
) {
    // Match full-walk ordering: default excludes win before unsupported-mode
    // coverage gaps, so excluded symlinks/gitlinks never flip scan status.
    if respect_default_excludes && crate::filesystem::is_default_excluded_path_bytes(path) {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Excluded);
        return;
    }
    if entry_mode.is_tree() {
        return;
    }
    if !entry_mode.is_blob() {
        let path_display = git_blob_path_display(path);
        let mode = format!("{entry_mode:?}");
        tracing::warn!(
            %oid,
            path = %path_display,
            %mode,
            "git tree diff entry is not a blob or tree; referenced content was NOT scanned"
        );
        record_git_object_unreadable();
        errors.push(git_unscanned_object_error(format!(
            "git tree entry '{path_display}' has unsupported mode {mode}; referenced content was not scanned"
        )));
        return;
    }
    let filepath = path.to_vec();
    if seen_blob_paths.insert((oid, filepath.clone())) {
        blob_metadata.push((oid, filepath));
    }
}

fn collect_tree_blobs_metadata(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
    seen_blob_paths: &mut HashSet<GitBlobPathKey>,
    walked_trees: &mut HashSet<gix::ObjectId>,
    tree_blob_oids: Option<&mut HashSet<gix::ObjectId>>,
    blob_metadata: &mut Vec<(gix::ObjectId, Vec<u8>)>,
    prefix: &[u8],
    errors: &mut Vec<SourceError>,
    respect_default_excludes: bool,
) {
    let mut visitor = HistoricalBlobCollector {
        seen_blob_paths,
        walked_trees,
        tree_blob_oids,
        blob_metadata,
        errors,
        respect_default_excludes,
        walk_errors: 0,
    };
    if let Err(error) = super::walk_tree_recursive(repo, tree, prefix, &mut visitor) {
        tracing::warn!(
            %error,
            "git tree walk failed; remaining blob(s) were NOT scanned"
        );
        record_git_object_unreadable();
        visitor.errors.push(git_unscanned_object_error(format!(
            "git tree walk failed ({error}); remaining blobs were not scanned"
        )));
    }
}

fn collect_ref_tip_oids(repo_arg: &str) -> Result<HashSet<gix::ObjectId>, SourceError> {
    let mut cmd = super::git_command()?;
    // Enumerate every ref under refs/ (notes, pull, replace, custom namespaces,
    // ...) so --max-commits still full-walks untouched tip blobs for tips that
    // `git log --all` can select. HEAD is unioned separately for detached CI.
    cmd.args([
        "-C",
        repo_arg,
        "for-each-ref",
        "--format=%(objectname) %(*objectname)",
        "--end-of-options",
    ]);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = super::spawn_git_child(cmd)?;
    let stdout = child
        .take_stdout()
        .ok_or_else(|| SourceError::Io(std::io::Error::other("missing for-each-ref stdout")))?;
    let mut reader = std::io::BufReader::new(stdout);
    let mut line_buf = Vec::new();
    let mut tips = HashSet::new();
    loop {
        let record =
            super::read_capped_line(&mut reader, &mut line_buf, super::GIT_PLUMBING_LINE_BYTES)
                .map_err(SourceError::Io)?;
        if record.consumed == 0 {
            break;
        }
        if record.content > super::GIT_PLUMBING_LINE_BYTES {
            return Err(super::git_output_line_truncated_error(
                "git for-each-ref",
                "ref object id line",
                super::GIT_PLUMBING_LINE_BYTES,
                record.content,
            ));
        }
        let line = String::from_utf8_lossy(&line_buf);
        let line = line.trim_end_matches('\n').trim_end_matches('\r');
        // Prefer the peeled target for annotated tags (`%(*objectname)`); fall
        // back to `%(objectname)` for commits/lightweight tags. Avoids the
        // newer `%(objectname:peel)` atom, which older git rejects.
        let mut fields = line.split_whitespace();
        let objectname = fields.next().unwrap_or("");
        let peeled = fields.next().unwrap_or("");
        let tip = if peeled.is_empty() {
            objectname
        } else {
            peeled
        };
        if let Some(id) = parse_git_object_id_line(tip, "ref tip") {
            tips.insert(id);
        }
    }
    super::wait_for_git_child(&mut child, "git for-each-ref", "enumerating ref tips")?;

    // Detached HEAD (common in CI) is enumerated by `git log --all` but is not
    // listed under refs/heads. Union the peeled HEAD tip so --max-commits still
    // full-walks the checked-out commit's untouched blobs.
    let mut head_cmd = super::git_command()?;
    head_cmd.args(["-C", repo_arg, "rev-parse", "--verify", "HEAD"]);
    head_cmd.stdout(std::process::Stdio::piped());
    head_cmd.stderr(std::process::Stdio::piped());
    match super::spawn_git_child(head_cmd) {
        Ok(mut head_child) => {
            if let Some(stdout) = head_child.take_stdout() {
                let mut reader = std::io::BufReader::new(stdout);
                let mut line_buf = Vec::new();
                if let Ok(record) = super::read_capped_line(
                    &mut reader,
                    &mut line_buf,
                    super::GIT_PLUMBING_LINE_BYTES,
                ) {
                    if record.consumed > 0 && record.content <= super::GIT_PLUMBING_LINE_BYTES {
                        let line = String::from_utf8_lossy(&line_buf);
                        let line = line.trim_end_matches('\n').trim_end_matches('\r');
                        if let Some(id) = parse_git_object_id_line(line, "HEAD tip") {
                            tips.insert(id);
                        }
                    }
                }
            }
            // Unborn/empty repos fail rev-parse; tip set simply stays without HEAD.
            let _ =
                super::wait_for_git_child(&mut head_child, "git rev-parse", "resolving HEAD tip");
        }
        Err(error) => {
            tracing::warn!(%error, "git HEAD tip could not be resolved; detached checkout may miss untouched blobs under --max-commits");
        }
    }

    Ok(tips)
}

/// Walk HEAD's tree and collect every blob path identity reachable from it.
///
/// Returns an empty set for an unborn/empty repository. Any failure after HEAD
/// resolves is a source error: otherwise live HEAD blobs can be mislabeled as
/// `git/history`, silently downgrading active leaks.
fn collect_head_blob_path_set(
    repo: &gix::Repository,
) -> Result<HashSet<GitBlobPathKey>, SourceError> {
    let head = repo.head().map_err(|error| {
        SourceError::Git(format!(
            "failed to read git HEAD while collecting live blob set: {error}"
        ))
    })?;
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
    let mut visitor = HeadBlobPathCollector { out: &mut out };
    super::walk_tree_recursive(repo, &tree, b"", &mut visitor)?;
    Ok(out)
}

struct HistoricalBlobCollector<'a> {
    seen_blob_paths: &'a mut HashSet<GitBlobPathKey>,
    walked_trees: &'a mut HashSet<gix::ObjectId>,
    tree_blob_oids: Option<&'a mut HashSet<gix::ObjectId>>,
    blob_metadata: &'a mut Vec<(gix::ObjectId, Vec<u8>)>,
    errors: &'a mut Vec<SourceError>,
    respect_default_excludes: bool,
    walk_errors: usize,
}

impl super::GitTreeVisitor for HistoricalBlobCollector<'_> {
    fn subtree_already_collected(&mut self, oid: &gix::ObjectId) -> bool {
        self.walked_trees.contains(oid)
    }

    fn note_subtree_collected(&mut self, oid: gix::ObjectId) {
        self.walked_trees.insert(oid);
    }

    fn walk_error_count(&self) -> usize {
        self.walk_errors
    }

    fn accept_path(&mut self, filepath: &[u8]) -> Result<bool, SourceError> {
        if self.respect_default_excludes
            && crate::filesystem::is_default_excluded_path_bytes(filepath)
        {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Excluded);
            return Ok(false);
        }
        Ok(true)
    }

    fn visit_blob(&mut self, oid: gix::ObjectId, filepath: Vec<u8>) -> Result<(), SourceError> {
        if let Some(tree_blob_oids) = self.tree_blob_oids.as_deref_mut() {
            tree_blob_oids.insert(oid.to_owned());
        }
        if self
            .seen_blob_paths
            .insert((oid.to_owned(), filepath.clone()))
        {
            self.blob_metadata.push((oid, filepath));
        }
        Ok(())
    }

    fn handle_entry_error(&mut self, error: String) -> Result<(), SourceError> {
        self.walk_errors += 1;
        // Law 10: a tree entry that fails to parse (corrupt/truncated tree
        // object) means the blob(s) it would reference are NOT scanned, an
        // UNKNOWN, not a clean tree. Surface loudly + count as unreadable so a
        // "0 findings --git" run is not mistaken for full history coverage.
        tracing::warn!(
            %error,
            "git tree entry could not be read (corrupt tree object); its blob(s) were NOT scanned"
        );
        record_git_object_unreadable();
        self.errors.push(git_unscanned_object_error(format!(
            "git tree entry could not be read ({error}); referenced blobs were not scanned"
        )));
        Ok(())
    }

    fn handle_subtree_object_error(
        &mut self,
        _filepath: &[u8],
        error: String,
    ) -> Result<(), SourceError> {
        self.walk_errors += 1;
        let path = String::from_utf8_lossy(_filepath);
        tracing::warn!(
            %error,
            %path,
            "git subtree object unreadable; its blob(s) were NOT scanned"
        );
        record_git_object_unreadable();
        self.errors.push(git_unscanned_object_error(format!(
            "git subtree '{path}' object unreadable ({error}); subtree blobs were not scanned"
        )));
        Ok(())
    }

    fn handle_subtree_type_error(
        &mut self,
        _filepath: &[u8],
        error: String,
    ) -> Result<(), SourceError> {
        self.walk_errors += 1;
        let path = String::from_utf8_lossy(_filepath);
        tracing::warn!(
            %error,
            %path,
            "git tree entry resolved to a non-tree object; its blob(s) were NOT scanned"
        );
        record_git_object_unreadable();
        self.errors.push(git_unscanned_object_error(format!(
            "git subtree '{path}' resolved to a non-tree object ({error}); subtree blobs were not scanned"
        )));
        Ok(())
    }

    fn handle_unscanned_entry(&mut self, filepath: &[u8], mode: String) -> Result<(), SourceError> {
        self.walk_errors += 1;
        let path = String::from_utf8_lossy(filepath);
        tracing::warn!(
            %path,
            mode,
            "git tree entry is not a blob or tree; referenced content was NOT scanned"
        );
        record_git_object_unreadable();
        self.errors.push(git_unscanned_object_error(format!(
            "git tree entry '{path}' has unsupported mode {mode}; referenced content was not scanned"
        )));
        Ok(())
    }
}

struct HeadBlobPathCollector<'a> {
    out: &'a mut HashSet<GitBlobPathKey>,
}

impl super::GitTreeVisitor for HeadBlobPathCollector<'_> {
    fn visit_blob(&mut self, oid: gix::ObjectId, filepath: Vec<u8>) -> Result<(), SourceError> {
        self.out.insert((oid, filepath));
        Ok(())
    }

    fn handle_entry_error(&mut self, error: String) -> Result<(), SourceError> {
        Err(SourceError::Git(format!(
            "failed to read git HEAD tree entry while collecting live blob set: {error}"
        )))
    }

    fn handle_subtree_object_error(
        &mut self,
        _filepath: &[u8],
        error: String,
    ) -> Result<(), SourceError> {
        Err(SourceError::Git(format!(
            "failed to read git HEAD subtree object while collecting live blob set: {error}"
        )))
    }

    fn handle_subtree_type_error(
        &mut self,
        _filepath: &[u8],
        error: String,
    ) -> Result<(), SourceError> {
        Err(SourceError::Git(format!(
            "git HEAD subtree object is not a tree while collecting live blob set: {error}"
        )))
    }
}
