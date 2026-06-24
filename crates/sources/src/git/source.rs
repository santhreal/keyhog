//! Git repository source: scans repository commits and extracts text blobs with
//! `gix`, stopping once the in-memory byte cap is reached.

use std::collections::{HashSet, VecDeque};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, Command};

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
const GIT_FSCK_LINE_BYTES: usize = 4096;

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
}

#[derive(Default)]
struct UnreachableGitObjects {
    commits: VecDeque<gix::ObjectId>,
    blobs: VecDeque<gix::ObjectId>,
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
        error: String,
    },
    NonBlob {
        oid: gix::ObjectId,
        kind: String,
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

/// Scans git blobs reachable from refs, reflogs, stashes, dangling commits, and
/// unreachable loose blobs.
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

struct GitCommitEnumerator {
    repo_arg: String,
    max_commits: Option<usize>,
    log_child: super::GitChild,
    log_lines: std::io::Lines<std::io::BufReader<ChildStdout>>,
    log_done: bool,
    unreachable_loaded: bool,
    unreachable_commits: VecDeque<gix::ObjectId>,
    unreachable_blobs: VecDeque<gix::ObjectId>,
}

impl GitCommitEnumerator {
    fn new(repo_arg: String, max_commits: Option<usize>) -> Result<Self, SourceError> {
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
            unreachable_commits: VecDeque::new(),
            unreachable_blobs: VecDeque::new(),
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
                        if let Some(id) = parse_git_object_id_line(&line, "commit")? {
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
                let unreachable = collect_unreachable_objects(&self.repo_arg, remaining)?;
                self.unreachable_commits = unreachable.commits;
                self.unreachable_blobs = unreachable.blobs;
                continue;
            }
            return Ok(None);
        }
    }

    fn take_unreachable_blobs(&mut self) -> VecDeque<gix::ObjectId> {
        std::mem::take(&mut self.unreachable_blobs)
    }
}

fn stream_git_blobs(
    repo_path: &Path,
    max_commits: Option<usize>,
    limits: crate::SourceLimits,
) -> Result<impl Iterator<Item = Result<Chunk, SourceError>>, SourceError> {
    let repo_arg = super::validate_repo_path(repo_path)?;
    let mut commit_ids = GitCommitEnumerator::new(repo_arg.clone(), max_commits)?;

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
    let head_blob_paths = collect_head_blob_path_set(&repo_handle)?;
    let mut current_tree_blobs: VecDeque<Chunk> = VecDeque::new();
    let mut seen_blob_paths: HashSet<GitBlobPathKey> = HashSet::new();
    let mut seen_commits: HashSet<gix::ObjectId> = HashSet::new();
    let mut unreachable_blobs: Option<VecDeque<gix::ObjectId>> = None;
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

            if let Some(cap) = super::git_history_cap_status(total_bytes, chunk_count, limits) {
                let error = super::record_git_history_cap_once(cap, &mut aggregate_cap_reported);
                done = true;
                return error.map(Err);
            }

            if unreachable_blobs.is_none() {
                let id = match commit_ids.next_id(seen_commits.len()) {
                    Ok(Some(id)) => id,
                    Ok(None) => {
                        unreachable_blobs = Some(commit_ids.take_unreachable_blobs());
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

                let commit_blobs =
                    match load_commit_blob_set(&repo_handle, id, &mut seen_blob_paths) {
                        Ok(Some(commit_blobs)) => commit_blobs,
                        Ok(None) => continue,
                        Err(error) => {
                            done = true;
                            return Some(Err(error));
                        }
                    };

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
                    ));

                    if let Some(chunk) = current_tree_blobs.pop_front() {
                        return Some(Ok(chunk));
                    }
                }
            } else if let Some(blobs) = unreachable_blobs.as_mut() {
                let blob_metadata = collect_unreachable_blob_metadata(blobs);
                if blob_metadata.is_empty() {
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
                    blob_metadata,
                    &mut total_bytes,
                    &mut chunk_count,
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
            return Ok(None);
        }
    };
    let commit = match obj.try_into_commit() {
        Ok(c) => c,
        Err(error) => {
            tracing::warn!(%error, commit = %commit_id, "git object is not a commit; its blobs were NOT scanned");
            record_git_object_unreadable();
            return Ok(None);
        }
    };
    let author = commit_author_name(&commit, &commit_id)?;
    let tree = match commit.tree() {
        Ok(t) => t,
        Err(error) => {
            tracing::warn!(%error, commit = %commit_id, "git commit tree unreadable; its blobs were NOT scanned");
            record_git_object_unreadable();
            return Ok(None);
        }
    };

    let mut blob_metadata = Vec::new();
    collect_tree_blobs_metadata(repo, &tree, seen_blob_paths, &mut blob_metadata, b"");

    Ok(Some(GitCommitBlobSet {
        commit_id,
        author,
        blob_metadata,
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
    ) -> VecDeque<Chunk> {
        self.decode_chunks(
            blob_metadata,
            GitBlobProvenance::Commit { commit_id, author },
            total_bytes,
            chunk_count,
        )
    }

    fn decode_unreachable_chunks(
        &self,
        blob_metadata: Vec<(gix::ObjectId, Vec<u8>)>,
        total_bytes: &mut usize,
        chunk_count: &mut usize,
    ) -> VecDeque<Chunk> {
        self.decode_chunks(
            blob_metadata,
            GitBlobProvenance::Unreachable,
            total_bytes,
            chunk_count,
        )
    }

    fn decode_chunks(
        &self,
        blob_metadata: Vec<(gix::ObjectId, Vec<u8>)>,
        provenance: GitBlobProvenance<'_>,
        total_bytes: &mut usize,
        chunk_count: &mut usize,
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
                            record_git_object_unreadable();
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
                    error: error.to_string(),
                }));
                continue;
            }
        };

        if header.kind() != Kind::Blob {
            batch.push(GitBlobBatchItem::Skip(GitBlobSkip::NonBlob {
                oid,
                kind: format!("{:?}", header.kind()),
            }));
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
            record_git_object_unreadable();
        }
        GitBlobSkip::NonBlob { oid, kind } => {
            tracing::warn!(
                %oid,
                kind,
                "git tree entry resolved to a non-blob object; blob NOT scanned"
            );
            record_git_object_unreadable();
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
            record_git_object_unreadable();
        }
        GitBlobSkip::ObjectUnreadable { oid, error } => {
            tracing::warn!(
                %error, %oid,
                "git blob object unreadable (corrupt/missing object); blob NOT scanned"
            );
            record_git_object_unreadable();
        }
        GitBlobSkip::Binary => {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
        }
    }
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

fn parse_git_object_id_line(
    line: &str,
    object_label: &'static str,
) -> Result<Option<gix::ObjectId>, SourceError> {
    let Some(object_id) = line.split_whitespace().next() else {
        return Ok(None);
    };
    match gix::ObjectId::from_hex(object_id.as_bytes()) {
        Ok(id) => Ok(Some(id)),
        Err(error) => {
            tracing::warn!(
                %error,
                object = object_id,
                object_kind = object_label,
                "git reported an unparsable object id; object NOT scanned"
            );
            record_git_object_unreadable();
            Ok(None)
        }
    }
}

fn collect_unreachable_objects(
    repo_arg: &str,
    remaining_commits: Option<usize>,
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
    while super::read_capped_line(&mut reader, &mut line_buf, GIT_FSCK_LINE_BYTES)
        .map_err(SourceError::Io)?
        > 0
    {
        let line = String::from_utf8_lossy(&line_buf);
        let line = line.trim_end_matches('\n').trim_end_matches('\r');
        if let Some(commit_id) = line.strip_prefix("unreachable commit ") {
            if remaining_commits.is_some_and(|limit| out.commits.len() >= limit) {
                continue;
            }
            let Some(id) = parse_git_object_id_line(commit_id, "commit")? else {
                continue;
            };
            out.commits.push_back(id);
            continue;
        }
        if let Some(blob_id) = line.strip_prefix("unreachable blob ") {
            let Some(id) = parse_git_object_id_line(blob_id, "blob")? else {
                continue;
            };
            out.blobs.push_back(id);
        }
    }
    super::wait_for_git_child(&mut child, "git fsck", "enumerating unreachable objects")?;
    Ok(out)
}

fn collect_unreachable_blob_metadata(
    blobs: &mut VecDeque<gix::ObjectId>,
) -> Vec<(gix::ObjectId, Vec<u8>)> {
    let mut metadata = Vec::new();
    while metadata.len() < GIT_PARALLEL_BLOB_BATCH_ITEMS {
        let Some(id) = blobs.pop_front() else {
            break;
        };
        metadata.push((id, format!(".git/unreachable/{id}").into_bytes()));
    }
    metadata
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
    blob_metadata: &mut Vec<(gix::ObjectId, Vec<u8>)>,
    prefix: &[u8],
) {
    let mut visitor = HistoricalBlobCollector {
        seen_blob_paths,
        blob_metadata,
    };
    if let Err(error) = super::walk_tree_recursive(repo, tree, prefix, &mut visitor) {
        tracing::warn!(
            %error,
            "git tree walk failed; remaining blob(s) were NOT scanned"
        );
        record_git_object_unreadable();
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
    blob_metadata: &'a mut Vec<(gix::ObjectId, Vec<u8>)>,
}

impl super::GitTreeVisitor for HistoricalBlobCollector<'_> {
    fn accept_path(&mut self, filepath: &[u8]) -> Result<bool, SourceError> {
        let default_exclude_path = String::from_utf8_lossy(filepath);
        if crate::filesystem::is_default_excluded_path(default_exclude_path.as_ref()) {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Excluded);
            return Ok(false);
        }
        Ok(true)
    }

    fn visit_blob(&mut self, oid: gix::ObjectId, filepath: Vec<u8>) -> Result<(), SourceError> {
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
        Ok(())
    }

    fn handle_subtree_object_error(
        &mut self,
        _filepath: &[u8],
        error: String,
    ) -> Result<(), SourceError> {
        tracing::warn!(
            %error,
            "git subtree object unreadable; its blob(s) were NOT scanned"
        );
        record_git_object_unreadable();
        Ok(())
    }

    fn handle_subtree_type_error(
        &mut self,
        _filepath: &[u8],
        error: String,
    ) -> Result<(), SourceError> {
        tracing::warn!(
            %error,
            "git tree entry resolved to a non-tree object; its blob(s) were NOT scanned"
        );
        record_git_object_unreadable();
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
        Ok(())
    }
}

fn record_git_object_unreadable() {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::GitObjectUnreadable);
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
