//! Git index source: scans the blob bytes that are actually staged.

use ignore::overrides::{Override, OverrideBuilder};
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::path::{Path, PathBuf};

const SOURCE_TYPE: &str = "git-staged";
const NO_STAGED_CONTENT_MESSAGE: &str = "no staged files found with added, copied, modified, renamed, or type-changed content; stage files first with `git add <path>`, or drop --git-staged to scan the working tree";

/// Scans added, copied, modified, renamed, and type-changed blobs from Git's
/// index. Working-tree bytes are never substituted for the staged object.
pub struct GitStagedSource {
    repo_path: PathBuf,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
    ignore_paths: Vec<String>,
}

impl GitStagedSource {
    /// Validate the repository and require at least one staged content change.
    ///
    /// This is intentionally fallible so CLI construction errors retain user-
    /// error semantics instead of becoming a coverage-gap exit after scanning
    /// has started. [`Source::chunks`] repeats the check through its raw diff,
    /// closing the race if the index changes after construction.
    pub fn try_new(repo_path: PathBuf) -> Result<Self, SourceError> {
        let repo_path = discover_worktree_root(&repo_path)?;
        let repo_arg = super::validate_repo_path(&repo_path)?;
        let mut command = super::git_command()?;
        command.args([
            "-C",
            &repo_arg,
            "diff",
            "--cached",
            "--quiet",
            "--no-renames",
            "--no-ext-diff",
            "--diff-filter=ACMT",
            "--end-of-options",
        ]);
        command.stdout(std::process::Stdio::null());
        command.stderr(std::process::Stdio::piped());
        let mut child = super::spawn_git_child(command)?;
        let status = child.wait()?;
        let stderr = child.stderr_excerpt();
        match status.code() {
            Some(1) => {}
            Some(0) => {
                return Err(SourceError::Git(NO_STAGED_CONTENT_MESSAGE.into()));
            }
            code => {
                return Err(SourceError::Git(format!(
                    "git diff --cached failed while validating staged input (exit {}): {}",
                    code.map_or_else(|| "signal".to_string(), |value| value.to_string()),
                    stderr.trim()
                )));
            }
        }
        Ok(Self {
            repo_path,
            limits: crate::SourceLimits::default(),
            respect_default_excludes: true,
            ignore_paths: Vec::new(),
        })
    }

    pub fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_default_excludes(mut self, respect: bool) -> Self {
        self.respect_default_excludes = respect;
        self
    }

    pub fn with_ignore_paths(mut self, paths: Vec<String>) -> Self {
        self.ignore_paths = paths;
        self
    }
}

fn discover_worktree_root(path: &Path) -> Result<PathBuf, SourceError> {
    let path = std::fs::canonicalize(path).map_err(|error| {
        SourceError::Other(format!(
            "failed to resolve staged-scan path '{}': {error}",
            path.display()
        ))
    })?;
    let repo = gix::discover(&path).map_err(|error| {
        SourceError::Git(format!(
            "'{}' is not inside a git worktree: {error}; run inside a repository or pass its path",
            path.display()
        ))
    })?;
    let worktree = repo.workdir().ok_or_else(|| {
        SourceError::Git(format!(
            "'{}' is a bare git repository without a staging worktree; --git-staged requires a worktree",
            path.display()
        ))
    })?;
    std::fs::canonicalize(worktree).map_err(|error| {
        SourceError::Other(format!(
            "failed to resolve discovered git worktree '{}': {error}",
            worktree.display()
        ))
    })
}

impl Source for GitStagedSource {
    fn name(&self) -> &str {
        SOURCE_TYPE
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        crate::gate_scan(|| {
            match StagedChunkIter::new(
                &self.repo_path,
                self.limits,
                self.respect_default_excludes,
                &self.ignore_paths,
            ) {
                Ok(chunks) => Box::new(chunks),
                Err(error) => Box::new(std::iter::once(Err(error))),
            }
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct StagedChunkIter {
    repo: gix::Repository,
    child: super::GitChild,
    reader: std::io::BufReader<std::process::ChildStdout>,
    ignore_matcher: Override,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
    header: Vec<u8>,
    raw_path: Vec<u8>,
    staged_records: usize,
    total_bytes: usize,
    chunk_count: usize,
    cap_reported: bool,
    done: bool,
}

impl StagedChunkIter {
    fn new(
        repo_path: &Path,
        limits: crate::SourceLimits,
        respect_default_excludes: bool,
        ignore_paths: &[String],
    ) -> Result<Self, SourceError> {
        let repo_root = super::canonical_repo_root(repo_path)?;
        let repo_arg = super::validate_repo_path(&repo_root)?;
        let ignore_matcher = build_ignore_matcher(&repo_root, ignore_paths)?;
        let repo = gix::open(&repo_root).map_err(|error| {
            SourceError::Git(format!(
                "failed to open repository for staged object reads: {error}"
            ))
        })?;

        // Raw mode gives the exact staged object id and its NUL-delimited path
        // in one index snapshot. Disabling rename detection represents a rename
        // as delete + add; the add carries the staged blob and avoids Git's
        // two-path raw record form.
        let mut command = super::git_command()?;
        command.args([
            "-C",
            &repo_arg,
            "diff",
            "--cached",
            "--raw",
            "-z",
            "--no-abbrev",
            "--no-renames",
            "--no-ext-diff",
            "--diff-filter=ACMT",
            "--end-of-options",
        ]);
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());

        let mut child = super::spawn_git_child(command)?;
        let stdout = child
            .take_stdout()
            .ok_or_else(|| SourceError::Io(std::io::Error::other("missing git diff stdout")))?;
        Ok(Self {
            repo,
            child,
            reader: std::io::BufReader::new(stdout),
            ignore_matcher,
            limits,
            respect_default_excludes,
            header: Vec::new(),
            raw_path: Vec::new(),
            staged_records: 0,
            total_bytes: 0,
            chunk_count: 0,
            cap_reported: false,
            done: false,
        })
    }

    fn stop(&mut self, error: SourceError) -> Option<Result<Chunk, SourceError>> {
        self.done = true;
        Some(Err(error))
    }

    fn finish(&mut self) -> Option<Result<Chunk, SourceError>> {
        self.done = true;
        if let Err(error) = super::wait_for_git_child(
            &mut self.child,
            "git diff --cached --raw",
            "reading staged blobs",
        ) {
            return Some(Err(error));
        }
        if self.staged_records == 0 {
            return Some(Err(SourceError::Git(NO_STAGED_CONTENT_MESSAGE.into())));
        }
        None
    }
}

impl Iterator for StagedChunkIter {
    type Item = Result<Chunk, SourceError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            let header_bytes = match super::read_capped_record(
                &mut self.reader,
                &mut self.header,
                super::GIT_PLUMBING_LINE_BYTES,
                0,
            ) {
                Ok(0) => return self.finish(),
                Ok(bytes) => bytes,
                Err(error) => return self.stop(SourceError::Io(error)),
            };
            if header_bytes > super::GIT_PLUMBING_LINE_BYTES {
                return self.stop(super::git_output_line_truncated_error(
                    "git staged source",
                    "raw diff header",
                    super::GIT_PLUMBING_LINE_BYTES,
                    header_bytes,
                ));
            }
            strip_record_delimiter(&mut self.header);
            let object_id = match parse_staged_object_id(&self.header) {
                Ok(object_id) => object_id,
                Err(error) => return self.stop(error),
            };

            let path_bytes = match super::read_capped_record(
                &mut self.reader,
                &mut self.raw_path,
                self.limits.git_line_bytes,
                0,
            ) {
                Ok(0) => {
                    return self.stop(SourceError::Git(
                        "git raw staged diff ended before the path for an index entry".into(),
                    ));
                }
                Ok(bytes) => bytes,
                Err(error) => return self.stop(SourceError::Io(error)),
            };
            if path_bytes > self.limits.git_line_bytes {
                return self.stop(super::git_output_line_truncated_error(
                    "git staged source",
                    "staged path",
                    self.limits.git_line_bytes,
                    path_bytes,
                ));
            }
            strip_record_delimiter(&mut self.raw_path);
            if self.raw_path.is_empty() {
                return self.stop(SourceError::Git(
                    "git raw staged diff emitted an empty path".into(),
                ));
            }
            self.staged_records = self.staged_records.saturating_add(1);

            let path = match git_path(&self.raw_path) {
                Ok(path) => path,
                Err(error) => return self.stop(error),
            };
            if self.ignore_matcher.matched(&path, false).is_ignore()
                || (self.respect_default_excludes
                    && crate::filesystem::is_default_excluded_path_bytes(&self.raw_path))
            {
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Excluded);
                continue;
            }

            if self.chunk_count >= self.limits.git_chunk_count {
                self.done = true;
                return super::record_git_cap_once(
                    super::GitHistoryCap::Chunks {
                        count: self.chunk_count,
                        cap: self.limits.git_chunk_count,
                    },
                    &mut self.cap_reported,
                    "git staged source",
                    "remaining staged blobs",
                )
                .map(Err);
            }

            let object = match self.repo.find_object(object_id) {
                Ok(object) => object,
                Err(error) => {
                    super::record_git_object_unreadable();
                    return Some(Err(super::git_unscanned_object_error(format!(
                        "staged object {object_id} at {} is unreadable ({error})",
                        path.to_string_lossy()
                    ))));
                }
            };
            if !object.kind.is_blob() {
                super::record_git_object_unreadable();
                return Some(Err(super::git_unscanned_object_error(format!(
                    "staged object {object_id} at {} has type {:?}, not blob",
                    path.to_string_lossy(),
                    object.kind
                ))));
            }
            let object_len = object.data.len();
            if object_len as u64 > self.limits.git_blob_bytes {
                let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
                return Some(Err(SourceError::Git(format!(
                    "staged blob at '{}' exceeds git_blob_bytes limit ({} > {}); blob was not scanned",
                    path.to_string_lossy(),
                    object_len,
                    self.limits.git_blob_bytes
                ))));
            }
            let next_total = self.total_bytes.saturating_add(object_len);
            if next_total > self.limits.git_total_bytes {
                self.done = true;
                return super::record_git_cap_once(
                    super::GitHistoryCap::TotalBytes {
                        total: next_total,
                        cap: self.limits.git_total_bytes,
                    },
                    &mut self.cap_reported,
                    "git staged source",
                    "remaining staged blobs",
                )
                .map(Err);
            }
            let Some(text) = crate::filesystem::decode_text_file(&object.data) else {
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                return Some(Err(SourceError::Git(format!(
                    "staged blob at '{}' decoded as binary/non-text; blob was not scanned",
                    path.to_string_lossy()
                ))));
            };
            if text.trim().is_empty() {
                continue;
            }

            self.total_bytes = next_total;
            self.chunk_count = self.chunk_count.saturating_add(1);
            return Some(Ok(Chunk {
                data: text.into(),
                metadata: ChunkMetadata {
                    base_offset: 0,
                    base_line: 0,
                    source_type: SOURCE_TYPE.into(),
                    path: Some(path.to_string_lossy().into_owned().into()),
                    commit: None,
                    author: None,
                    date: None,
                    mtime_ns: None,
                    size_bytes: Some(object_len as u64),
                    decoded_span: None,
                },
            }));
        }
    }
}

fn build_ignore_matcher(root: &Path, ignore_paths: &[String]) -> Result<Override, SourceError> {
    let mut builder = OverrideBuilder::new(root);
    for pattern in ignore_paths {
        let pattern = if pattern.starts_with('!') {
            pattern.clone()
        } else {
            format!("!{pattern}")
        };
        builder.add(&pattern).map_err(|error| {
            SourceError::Other(format!(
                "invalid staged-scan ignore pattern {pattern:?}: {error}"
            ))
        })?;
    }
    builder.build().map_err(|error| {
        SourceError::Other(format!(
            "failed to build staged-scan ignore policy: {error}"
        ))
    })
}

fn parse_staged_object_id(header: &[u8]) -> Result<gix::ObjectId, SourceError> {
    let Some(header) = header.strip_prefix(b":") else {
        return Err(SourceError::Git(
            "git raw staged diff emitted a record without ':' front matter".into(),
        ));
    };
    let mut fields = header
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let object_id = match (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) {
        (Some(_old_mode), Some(_new_mode), Some(_old_id), Some(id), Some(_status), None) => id,
        _ => {
            let count = header
                .split(|byte| byte.is_ascii_whitespace())
                .filter(|field| !field.is_empty())
                .count();
            return Err(SourceError::Git(format!(
                "git raw staged diff emitted {count} header fields; expected 5"
            )));
        }
    };
    gix::ObjectId::from_hex(object_id).map_err(|error| {
        SourceError::Git(format!(
            "git raw staged diff emitted an invalid staged object id: {error}"
        ))
    })
}

fn strip_record_delimiter(record: &mut Vec<u8>) {
    if record.last() == Some(&0) {
        record.pop();
    }
}

#[cfg(unix)]
fn git_path(raw: &[u8]) -> Result<PathBuf, SourceError> {
    use std::os::unix::ffi::OsStrExt;
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(raw)))
}

#[cfg(not(unix))]
fn git_path(raw: &[u8]) -> Result<PathBuf, SourceError> {
    let path = std::str::from_utf8(raw).map_err(|error| {
        SourceError::Git(format!(
            "git reported a staged path that is not valid UTF-8 on this platform: {error}"
        ))
    })?;
    Ok(PathBuf::from(path))
}
