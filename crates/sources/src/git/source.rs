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
/// are skipped entirely — secrets almost never appear in 10+ MiB files.
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

    // Get commit hashes from ALL refs — branches, tags, dangling commits.
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
    // repo opened the repo 10k times — fd churn + IO amplification.
    let repo_owned = repo_path.to_path_buf();
    let repo_handle = gix::open(&repo_owned)
        .map_err(|e| SourceError::Io(std::io::Error::other(format!("gix open: {e}"))))?;
    // Snapshot every blob OID reachable from HEAD's tree. Used to label
    // emitted chunks as "git/head" (live in HEAD) vs "git/history"
    // (only present in older commits). The downstream scorer downgrades
    // the severity of `git/history` findings — a credential a developer
    // already removed from HEAD is still a leak, but less urgent than
    // one currently grep-able from main. Cheap: one tree walk at most.
    let head_blobs = collect_head_blob_set(&repo_handle).unwrap_or_default();
    let mut current_tree_blobs: VecDeque<Chunk> = VecDeque::new();
    let mut seen_blobs: HashSet<gix::ObjectId> = HashSet::new();
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
            let Ok(obj) = repo.find_object(id) else {
                continue;
            };
            let Ok(commit) = obj.try_into_commit() else {
                continue;
            };
            let Ok(tree) = commit.tree() else {
                continue;
            };

            let mut chunks = Vec::new();
            collect_tree_blobs_to_vec(
                repo,
                &tree,
                commit_id,
                author,
                &head_blobs,
                &mut seen_blobs,
                &mut chunks,
                &mut total_bytes,
                &mut chunk_count,
                b"",
            );

            if !chunks.is_empty() {
                current_tree_blobs.extend(chunks);
                if let Some(chunk) = current_tree_blobs.pop_front() {
                    return Some(Ok(chunk));
                }
            }
        }
    }))
}

fn collect_tree_blobs_to_vec(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
    commit_id: &str,
    author: &str,
    head_blobs: &HashSet<gix::ObjectId>,
    seen_blobs: &mut HashSet<gix::ObjectId>,
    chunks: &mut Vec<Chunk>,
    total_bytes: &mut usize,
    chunk_count: &mut usize,
    prefix: &[u8],
) {
    if *total_bytes >= MAX_GIT_TOTAL_BYTES || *chunk_count >= MAX_GIT_CHUNKS {
        return;
    }
    for entry_ref in tree.iter() {
        if *total_bytes >= MAX_GIT_TOTAL_BYTES || *chunk_count >= MAX_GIT_CHUNKS {
            return;
        }
        let entry = match entry_ref {
            Ok(e) => e,
            Err(_) => continue,
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

        let mode = entry.mode();

        if mode.is_tree() {
            if let Ok(obj) = repo.find_object(oid) {
                if let Ok(subtree) = obj.try_into_tree() {
                    collect_tree_blobs_to_vec(
                        repo,
                        &subtree,
                        commit_id,
                        author,
                        head_blobs,
                        seen_blobs,
                        chunks,
                        total_bytes,
                        chunk_count,
                        &filepath,
                    );
                }
            }
            continue;
        }

        if !mode.is_blob() {
            continue;
        }

        if !seen_blobs.insert(oid) {
            continue;
        }

        let header = match repo.find_header(oid) {
            Ok(header) => header,
            Err(_) => continue,
        };
        if header.kind() != Kind::Blob || header.size() > MAX_GIT_BLOB_BYTES {
            continue;
        }

        let obj = match repo.find_object(oid) {
            Ok(o) => o,
            Err(_) => continue,
        };

        let file_text = match std::str::from_utf8(&obj.data) {
            Ok(text) => text.to_string(),
            Err(_) => continue,
        };

        let path = String::from_utf8_lossy(&filepath).to_string();
        *total_bytes = total_bytes.saturating_add(file_text.len());
        *chunk_count += 1;

        let in_head = head_blobs.contains(&oid);
        chunks.push(Chunk {
            data: file_text.into(),
            metadata: ChunkMetadata {
                base_offset: 0,
                source_type: if in_head { "git/head" } else { "git/history" }.into(),
                path: Some(path),
                commit: Some(commit_id.to_string()),
                author: Some(author.to_string()),
                date: None,
            },
        });
    }
}

/// Walk HEAD's tree and collect every blob OID reachable from it.
///
/// Returns an empty set if HEAD doesn't resolve (detached, empty repo, or
/// transient I/O error). The caller's behavior in that case: every blob is
/// labeled `git/history` since we cannot prove it sits in HEAD — safer than
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
