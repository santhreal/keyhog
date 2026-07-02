//! Git repository source: scans repository commits and extracts text blobs with
//! `gix`, stopping once the in-memory byte cap is reached.

use std::collections::{HashSet, VecDeque};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, Command};

use gix::objs::Kind;
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use rayon::prelude::*;

use super::tag_messages::{
    collect_reachable_tag_messages, decode_tag_message_chunks,
    decode_unreachable_tag_message_chunks,
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

struct GitCommitBlobSet {
    commit_id: String,
    author: String,
    blob_metadata: Vec<(gix::ObjectId, Vec<u8>)>,
    errors: Vec<SourceError>,
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
enum GitBlobDecodeOutcome {
    Decoded(DecodedGitBlob),
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
    RepositoryOpen {
        oid: gix::ObjectId,
        filepath: Vec<u8>,
        error: String,
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
    max_commits: Option<usize>,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
}

/// Single source of truth for the `with_max_commits` builder setting shared by
/// `GitSource` and `GitHistorySource`. Both builders store the requested commit
/// cap identically as `Some(n)`; centralizing the conversion here keeps the two
/// byte-identical setters from drifting and gives any future clamp/normalize
/// policy exactly one place to live. `history.rs` delegates via
/// `super::source::max_commits_limit`.
pub(super) fn max_commits_limit(n: usize) -> Option<usize> {
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
            match stream_git_blobs(
                &self.repo_path,
                self.max_commits,
                self.limits,
                self.respect_default_excludes,
            ) {
                Ok(iter) => Box::new(iter),
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
    log_lines: std::io::Lines<std::io::BufReader<ChildStdout>>,
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
        let mut log_child = super::spawn_git_child(log_cmd)?;
        let log_stdout = log_child
            .take_stdout()
            .ok_or_else(|| SourceError::Io(std::io::Error::other("missing log stdout")))?;
        let log_lines = std::io::BufReader::new(log_stdout).lines();

        Ok(Self {
            repo_arg,
            max_commits,
            log_child,
            log_lines,
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
                match self.log_lines.next() {
                    Some(Ok(line)) => {
                        if let Some(id) = parse_git_object_id_line(&line, "commit") {
                            return Ok(Some(id));
                        }
                        continue;
                    }
                    Some(Err(error)) => return Err(SourceError::Io(error)),
                    None => {
                        self.log_done = true;
                        super::wait_for_git_child(
                            &mut self.log_child,
                            "git log",
                            "enumerating git commits",
                        )?;
                        continue;
                    }
                }
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
    let mut unreachable_objects: Option<UnreachableGitObjects> = None;
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
                        current_tree_blobs.extend(decode_tag_message_chunks(
                            &repo_handle,
                            &mut reachable_tags,
                            limits,
                            &mut total_bytes,
                            &mut chunk_count,
                            &mut pending_errors,
                        ));
                        if let Some(chunk) = current_tree_blobs.pop_front() {
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

                let commit_blobs = match load_commit_blob_set(
                    &repo_handle,
                    id,
                    &mut seen_blob_paths,
                    respect_default_excludes,
                ) {
                    Ok(Some(commit_blobs)) => commit_blobs,
                    Ok(None) => continue,
                    Err(error) => {
                        done = true;
                        return Some(Err(error));
                    }
                };
                pending_errors.extend(commit_blobs.errors);

                if !commit_blobs.blob_metadata.is_empty() {
                    let chunk_decoder = GitBlobChunkDecoder {
                        repo: &repo_handle,
                        repo_path: &repo_owned,
                        head_blob_paths: &head_blob_paths,
                        limits,
                    };
                    current_tree_blobs.extend(chunk_decoder.decode_commit_chunks(
                        commit_blobs.blob_metadata,
                        &commit_blobs.commit_id,
                        &commit_blobs.author,
                        &mut total_bytes,
                        &mut chunk_count,
                        &mut pending_errors,
                    ));

                    if let Some(chunk) = current_tree_blobs.pop_front() {
                        return Some(Ok(chunk));
                    }
                }
            } else if let Some(objects) = unreachable_objects.as_mut() {
                current_tree_blobs.extend(decode_unreachable_tag_message_chunks(
                    &repo_handle,
                    &mut objects.tags,
                    limits,
                    &mut total_bytes,
                    &mut chunk_count,
                    &mut pending_errors,
                ));
                if let Some(chunk) = current_tree_blobs.pop_front() {
                    return Some(Ok(chunk));
                }

                let blob_metadata = collect_unreachable_non_commit_blob_metadata(
                    &repo_handle,
                    objects,
                    &mut seen_blob_paths,
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

                let chunk_decoder = GitBlobChunkDecoder {
                    repo: &repo_handle,
                    repo_path: &repo_owned,
                    head_blob_paths: &head_blob_paths,
                    limits,
                };
                current_tree_blobs.extend(chunk_decoder.decode_unreachable_chunks(
                    blob_metadata.metadata,
                    &mut total_bytes,
                    &mut chunk_count,
                    &mut pending_errors,
                ));

                if let Some(chunk) = current_tree_blobs.pop_front() {
                    return Some(Ok(chunk));
                }
            }
        }
    }))
}

fn load_commit_blob_set(
    repo: &gix::Repository,
    id: gix::ObjectId,
    seen_blob_paths: &mut HashSet<GitBlobPathKey>,
    respect_default_excludes: bool,
) -> Result<Option<GitCommitBlobSet>, SourceError> {
    let commit_id = id.to_string();
    // Law 10: `git log` already enumerated this commit, so a gix failure to
    // load its object / commit / tree means a commit's blobs are NOT
    // scanned (corrupt object, partial clone missing the tree). Count each
    // as unreadable + warn so the dropped commit is operator-visible rather
    // than a silent `continue` that reads as full history coverage.
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
    collect_tree_blobs_metadata(
        repo,
        &tree,
        seen_blob_paths,
        None,
        &mut blob_metadata,
        b"",
        &mut errors,
        respect_default_excludes,
    );

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
    fn decode_commit_chunks(
        &self,
        blob_metadata: Vec<(gix::ObjectId, Vec<u8>)>,
        commit_id: &str,
        author: &str,
        total_bytes: &mut usize,
        chunk_count: &mut usize,
        pending_errors: &mut VecDeque<SourceError>,
    ) -> VecDeque<Chunk> {
        self.decode_chunks(
            blob_metadata,
            GitBlobProvenance::Commit { commit_id, author },
            total_bytes,
            chunk_count,
            pending_errors,
        )
    }

    fn decode_unreachable_chunks(
        &self,
        blob_metadata: Vec<(gix::ObjectId, Vec<u8>)>,
        total_bytes: &mut usize,
        chunk_count: &mut usize,
        pending_errors: &mut VecDeque<SourceError>,
    ) -> VecDeque<Chunk> {
        self.decode_chunks(
            blob_metadata,
            GitBlobProvenance::Unreachable,
            total_bytes,
            chunk_count,
            pending_errors,
        )
    }

    fn decode_chunks(
        &self,
        blob_metadata: Vec<(gix::ObjectId, Vec<u8>)>,
        provenance: GitBlobProvenance<'_>,
        total_bytes: &mut usize,
        chunk_count: &mut usize,
        pending_errors: &mut VecDeque<SourceError>,
    ) -> VecDeque<Chunk> {
        let mut chunks = VecDeque::new();
        let mut blob_metadata = blob_metadata.into_iter();

        'blob_batches: loop {
            if super::git_history_cap_status(*total_bytes, *chunk_count, self.limits).is_some() {
                break;
            }

            let batch = next_git_blob_batch(self.repo, &mut blob_metadata, self.limits);
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
                decode_git_blob_candidates_parallel(self.repo_path, candidates).into_iter();

            for item in batch {
                if super::git_history_cap_status(*total_bytes, *chunk_count, self.limits).is_some()
                {
                    break 'blob_batches;
                }

                let decoded_blob = match item {
                    GitBlobBatchItem::Skip(skip) => {
                        record_git_blob_skip(skip, pending_errors);
                        continue;
                    }
                    GitBlobBatchItem::Candidate(candidate) => match decoded.next() {
                        Some(GitBlobDecodeOutcome::Decoded(decoded_blob)) => decoded_blob,
                        Some(GitBlobDecodeOutcome::Skip(skip)) => {
                            record_git_blob_skip(skip, pending_errors);
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
                    },
                };

                let chunk = self.chunk_from_decoded_blob(decoded_blob, provenance);
                *total_bytes = total_bytes.saturating_add(chunk.data.len());
                *chunk_count += 1;
                chunks.push_back(chunk);
            }
        }

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
                path: Some(path),
                commit,
                author,
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
                    filepath,
                    error: error.to_string(),
                }));
                continue;
            }
        };

        if header.kind() != Kind::Blob {
            batch.push(GitBlobBatchItem::Skip(GitBlobSkip::NonBlob {
                oid,
                filepath,
                kind: format!("{:?}", header.kind()),
            }));
            continue;
        }

        let size_bytes = header.size();
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
                    filepath: candidate.filepath,
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
                filepath: candidate.filepath,
                error: error.to_string(),
            });
        }
    };

    let Some(file_text) = decode_git_blob(&obj.data) else {
        return GitBlobDecodeOutcome::Skip(GitBlobSkip::Binary {
            oid: candidate.oid,
            filepath: candidate.filepath,
        });
    };

    GitBlobDecodeOutcome::Decoded(DecodedGitBlob {
        oid: candidate.oid,
        filepath: candidate.filepath,
        size_bytes: candidate.size_bytes,
        file_text,
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
        GitBlobSkip::RepositoryOpen {
            oid,
            filepath,
            error,
        } => {
            tracing::warn!(
                %error, %oid,
                "git repository could not be opened by a blob decode worker; blob NOT scanned"
            );
            record_git_object_unreadable();
            pending_errors.push_back(git_unscanned_object_error(format!(
                "git repository could not be opened while decoding blob {oid} at {} ({error}); blob was not scanned",
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
    let mut command = Command::new(super::git_bin()?);
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

fn collect_tree_blobs_metadata(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
    seen_blob_paths: &mut HashSet<GitBlobPathKey>,
    tree_blob_oids: Option<&mut HashSet<gix::ObjectId>>,
    blob_metadata: &mut Vec<(gix::ObjectId, Vec<u8>)>,
    prefix: &[u8],
    errors: &mut Vec<SourceError>,
    respect_default_excludes: bool,
) {
    let mut visitor = HistoricalBlobCollector {
        seen_blob_paths,
        tree_blob_oids,
        blob_metadata,
        errors,
        respect_default_excludes,
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
    tree_blob_oids: Option<&'a mut HashSet<gix::ObjectId>>,
    blob_metadata: &'a mut Vec<(gix::ObjectId, Vec<u8>)>,
    errors: &'a mut Vec<SourceError>,
    respect_default_excludes: bool,
}

impl super::GitTreeVisitor for HistoricalBlobCollector<'_> {
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
        // Law 10: a tree entry that fails to parse (corrupt/truncated tree
        // object) means the blob(s) it would reference are NOT scanned — an
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_source_with_max_commits_routes_through_the_shared_owner() {
        // The shared owner stores the requested cap verbatim as `Some(n)`, and
        // the GitSource builder must route through it (no divergent copy).
        assert_eq!(max_commits_limit(7), Some(7));
        let source = GitSource::new(PathBuf::from(".")).with_max_commits(5);
        assert_eq!(source.max_commits, Some(5));
        assert_eq!(source.max_commits, max_commits_limit(5));
    }

    #[test]
    fn max_commits_limit_zero_is_an_explicit_cap_not_clamped_away() {
        // Zero is a valid explicit "scan no commits" cap (git log --max-count 0),
        // not "unlimited" (None): it must survive as Some(0), never be clamped.
        assert_eq!(max_commits_limit(0), Some(0));
        let source = GitSource::new(PathBuf::from(".")).with_max_commits(0);
        assert_eq!(source.max_commits, Some(0));
    }
}
