//! Git diff source: scans only added/modified lines from `git diff`, ideal for
//! CI/CD pre-commit hooks that should only flag new secrets.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::collections::VecDeque;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// Scans only the ADDED lines between two git refs.
/// Uses `git diff` unified diff output and extracts lines starting with '+'.
/// Useful for CI/CD pre-commit hooks and PR checks.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::Source;
/// use keyhog_sources::GitDiffSource;
/// use std::path::PathBuf;
///
/// let source = GitDiffSource::new(PathBuf::from("."), "main").with_head_ref("HEAD");
/// assert_eq!(source.name(), "git-diff");
/// ```
pub struct GitDiffSource {
    repo_path: PathBuf,
    base_ref: String,
    head_ref: Option<String>,
    limits: crate::SourceLimits,
}

impl GitDiffSource {
    /// Create a new diff source comparing `base_ref` to HEAD.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::GitDiffSource;
    /// use std::path::PathBuf;
    ///
    /// let source = GitDiffSource::new(PathBuf::from("."), "origin/main");
    /// assert_eq!(source.name(), "git-diff");
    /// ```
    pub fn new(repo_path: PathBuf, base_ref: impl Into<String>) -> Self {
        Self {
            repo_path,
            base_ref: base_ref.into(),
            head_ref: None,
            limits: crate::SourceLimits::default(),
        }
    }

    /// Set a specific head ref to compare against (defaults to HEAD).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::GitDiffSource;
    /// use std::path::PathBuf;
    ///
    /// let source = GitDiffSource::new(PathBuf::from("."), "main").with_head_ref("feature");
    /// assert_eq!(source.name(), "git-diff");
    /// ```
    pub fn with_head_ref(mut self, head_ref: impl Into<String>) -> Self {
        self.head_ref = Some(head_ref.into());
        self
    }

    pub fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl Source for GitDiffSource {
    fn name(&self) -> &str {
        "git-diff"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match stream_added_lines(
            &self.repo_path,
            &self.base_ref,
            self.head_ref.as_deref(),
            self.limits,
        ) {
            Ok(iter) => Box::new(iter),
            Err(e) => Box::new(std::iter::once(Err(e))),
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Stream only ADDED lines from git diff output.
fn stream_added_lines(
    repo_path: &Path,
    base_ref: &str,
    head_ref: Option<&str>,
    limits: crate::SourceLimits,
) -> Result<impl Iterator<Item = Result<Chunk, SourceError>>, SourceError> {
    let base_ref = super::validate_ref_name(base_ref)?;
    let head_ref = head_ref.map(super::validate_ref_name).transpose()?;
    let repo_root = super::canonical_repo_root(repo_path)?;
    let repo_arg = super::validate_repo_path(&repo_root)?;

    // Resolve refs once each; `rev-parse --verify` both validates and returns
    // the canonical commit hash used by the diff command.
    let base_commit = super::resolve_commit_hash(&repo_arg, &base_ref)?;
    let head_commit = if let Some(head_ref) = head_ref.as_deref() {
        Some(super::resolve_commit_hash(&repo_arg, head_ref)?)
    } else {
        None
    };

    // Run git diff to get unified diff output
    let mut command = Command::new(super::git_bin()?);
    command.args([
        "-C",
        &repo_arg,
        "diff",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "-U0",
        "--end-of-options",
    ]);
    command.arg(&base_commit);
    if let Some(head_commit) = head_commit.as_deref() {
        command.arg(head_commit);
    }

    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = super::spawn_git_child(command)?;
    let stdout = child
        .take_stdout()
        .ok_or_else(|| SourceError::Io(std::io::Error::other("missing stdout")))?;
    let mut reader = std::io::BufReader::new(stdout);

    // Get commit info for metadata
    let metadata_commit = head_commit.unwrap_or_else(|| base_commit.clone()); // LAW10: absent verify-spec field => documented default (GET / AuthSpec::None / first); recall-safe
    let metadata = super::get_commit_metadata(&repo_arg, &metadata_commit)?;
    let mut untracked_chunks = if head_ref.is_none() {
        Some(UntrackedWorktreeChunks::new(
            repo_arg.clone(),
            repo_root.clone(),
            metadata_commit.clone(),
            metadata.author.clone(),
            metadata.date.clone(),
            limits,
        ))
    } else {
        None
    };

    let mut current_path: Option<String> = None;
    let mut current_content = Vec::new();
    let mut diff_parser = super::UnifiedDiffParser::new();
    let mut done = false;
    let mut emit_untracked = false;
    let mut wait_after_final_chunk = false;
    let mut pending_errors: VecDeque<SourceError> = VecDeque::new();
    let mut line_buf: Vec<u8> = Vec::new();
    let hunk_byte_cap = super::git_blob_bytes_limit_usize(limits);
    let mut total_bytes = 0usize;
    let mut chunk_count = 0usize;
    let mut aggregate_cap_reported = false;
    // New-file line BEFORE the current hunk's first added line (i.e. the
    // hunk header's `+new_start - 1`). The scanner counts a match's line
    // within the chunk text from 1; adding this base yields the absolute
    // new-file line. With `-U0` a hunk's added lines are the contiguous
    // run `new_start, new_start+1, …`, so one base per hunk is exact.
    // Each hunk is emitted as its own chunk so its base applies cleanly;
    // without this every diff finding reported line 1 (the chunk-local
    // line of the concatenated added-line blob).
    let mut current_base_line: usize = 0;

    Ok(std::iter::from_fn(move || {
        if wait_after_final_chunk {
            wait_after_final_chunk = false;
            match super::wait_for_git_child(&mut child, "git diff", "enumerating changed lines") {
                Ok(()) => emit_untracked = true,
                Err(error) => {
                    done = true;
                    return Some(Err(error));
                }
            }
        }
        if let Some(error) = pending_errors.pop_front() {
            return Some(Err(error));
        }
        if emit_untracked {
            let Some(scanner) = untracked_chunks.as_mut() else {
                done = true;
                return None;
            };
            match scanner.next_row(
                &mut total_bytes,
                &mut chunk_count,
                &mut aggregate_cap_reported,
            ) {
                Ok(Some(Ok(chunk))) => return Some(Ok(chunk)),
                Ok(Some(Err(error))) => return Some(Err(error)),
                Ok(None) => {
                    done = true;
                    return None;
                }
                Err(error) => {
                    done = true;
                    return Some(Err(error));
                }
            }
        }
        if done {
            return None;
        }
        if let Some(cap) = super::git_history_cap_status(total_bytes, chunk_count, limits) {
            let error = super::record_git_cap_once(
                cap,
                &mut aggregate_cap_reported,
                "git diff source",
                "remaining changed lines",
            );
            done = true;
            return error.map(Err);
        }

        loop {
            let line =
                match super::read_capped_line(&mut reader, &mut line_buf, limits.git_line_bytes) {
                    Ok(n) if n > limits.git_line_bytes => {
                        return Some(Err(super::git_output_line_truncated_error(
                            "git diff source",
                            "unified diff line",
                            limits.git_line_bytes,
                            n,
                        )));
                    }
                    Ok(n) if n > 0 => super::trim_diff_line_bytes(&line_buf),
                    Err(e) => {
                        done = true;
                        return Some(Err(SourceError::Io(e)));
                    }
                    Ok(_) => {
                        if let Some(ref path) = current_path {
                            if let Some(chunk_content) =
                                super::drain_trimmed_hunk(&mut current_content)
                            {
                                wait_after_final_chunk = true;
                                return Some(Ok(make_git_diff_chunk(
                                    chunk_content,
                                    current_base_line,
                                    path,
                                    &metadata_commit,
                                    &metadata.author,
                                    &metadata.date,
                                    &mut total_bytes,
                                    &mut chunk_count,
                                )));
                            }
                        }
                        match super::wait_for_git_child(
                            &mut child,
                            "git diff",
                            "enumerating changed lines",
                        ) {
                            Ok(()) => {
                                emit_untracked = true;
                                let Some(scanner) = untracked_chunks.as_mut() else {
                                    done = true;
                                    return None;
                                };
                                match scanner.next_row(
                                    &mut total_bytes,
                                    &mut chunk_count,
                                    &mut aggregate_cap_reported,
                                ) {
                                    Ok(Some(Ok(chunk))) => return Some(Ok(chunk)),
                                    Ok(Some(Err(error))) => return Some(Err(error)),
                                    Ok(None) => {
                                        done = true;
                                        return None;
                                    }
                                    Err(error) => {
                                        done = true;
                                        return Some(Err(error));
                                    }
                                }
                            }
                            Err(error) => {
                                done = true;
                                return Some(Err(error));
                            }
                        }
                    }
                };

            let event = match diff_parser.parse_line(line, "git diff") {
                Ok(event) => event,
                Err(error) => {
                    done = true;
                    return Some(Err(error));
                }
            };

            match event {
                super::UnifiedDiffEvent::FileHeader {
                    new_path,
                    invalid_path,
                } => {
                    let prev_path = current_path.take();
                    let prev_content = super::drain_trimmed_hunk(&mut current_content);
                    let prev_base_line = current_base_line;

                    // New file: its first `@@` will set the base for its hunks.
                    current_base_line = 0;
                    if invalid_path {
                        tracing::warn!(
                            "git diff file header path failed sanitization; added lines for that file were NOT scanned"
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                        pending_errors.push_back(SourceError::Other(
                            "git diff file header path failed sanitization; added lines for that file were NOT scanned"
                                .into(),
                        ));
                    }
                    current_path = match new_path {
                        Some(path) if crate::filesystem::is_default_excluded_path(&path) => {
                            let _event = crate::record_skip_event(crate::SourceSkipEvent::Excluded);
                            None
                        }
                        path => path,
                    };

                    if let Some(path) = prev_path {
                        if let Some(prev_content) = prev_content {
                            return Some(Ok(make_git_diff_chunk(
                                prev_content,
                                prev_base_line,
                                &path,
                                &metadata_commit,
                                &metadata.author,
                                &metadata.date,
                                &mut total_bytes,
                                &mut chunk_count,
                            )));
                        }
                    }
                    if let Some(error) = pending_errors.pop_front() {
                        return Some(Err(error));
                    }
                    continue;
                }
                super::UnifiedDiffEvent::DeletedFile => {
                    current_path = None;
                    current_content.clear();
                    current_base_line = 0;
                    continue;
                }
                super::UnifiedDiffEvent::Metadata => continue,
                super::UnifiedDiffEvent::HunkStart { base_line } => {
                    // Start of a new hunk: flush the previous hunk as its own
                    // chunk (so its base line applies cleanly), then adopt this
                    // hunk's new-file start as the base for the lines that follow.
                    let prev_content = super::drain_trimmed_hunk(&mut current_content);
                    let prev_base_line = current_base_line;
                    current_base_line = base_line;
                    if let Some(ref path) = current_path {
                        if let Some(prev_content) = prev_content {
                            return Some(Ok(make_git_diff_chunk(
                                prev_content,
                                prev_base_line,
                                path,
                                &metadata_commit,
                                &metadata.author,
                                &metadata.date,
                                &mut total_bytes,
                                &mut chunk_count,
                            )));
                        }
                    }
                    continue;
                }
                super::UnifiedDiffEvent::AddedLine(bytes) => {
                    if current_path.is_none() {
                        continue;
                    }
                    current_content.extend_from_slice(bytes);
                    current_content.push(b'\n');
                }
                super::UnifiedDiffEvent::BinaryFile => {
                    current_path = None;
                    current_content.clear();
                    current_base_line = 0;
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                    continue;
                }
                super::UnifiedDiffEvent::Other => {}
            }

            if current_content.len() > hunk_byte_cap {
                if let Some(ref path) = current_path {
                    let emitted_lines = memchr::memchr_iter(b'\n', &current_content).count();
                    if let Some(chunk_content) = super::drain_trimmed_hunk(&mut current_content) {
                        let flush_base_line = current_base_line;
                        // Mid-hunk flush of a single over-cap hunk: the lines
                        // that follow continue the SAME hunk, so advance the
                        // base by the lines we are emitting now to keep their
                        // attribution correct after the buffer resets.
                        current_base_line = current_base_line.saturating_add(emitted_lines);
                        return Some(Ok(make_git_diff_chunk(
                            chunk_content,
                            flush_base_line,
                            path,
                            &metadata_commit,
                            &metadata.author,
                            &metadata.date,
                            &mut total_bytes,
                            &mut chunk_count,
                        )));
                    }
                }
            }
        }
    }))
}

fn make_git_diff_chunk(
    content: String,
    base_line: usize,
    path: &str,
    commit: &str,
    author: &str,
    date: &str,
    total_bytes: &mut usize,
    chunk_count: &mut usize,
) -> Chunk {
    *total_bytes = total_bytes.saturating_add(content.len());
    *chunk_count = chunk_count.saturating_add(1);
    Chunk {
        data: content.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line,
            source_type: "git-diff".into(),
            path: Some(path.to_string()),
            commit: Some(commit.to_string()),
            author: Some(author.to_string()),
            date: Some(date.to_string()),
            mtime_ns: None,
            size_bytes: None,
            decoded_span: None,
        },
    }
}

struct UntrackedWorktreeChunks {
    repo_arg: String,
    repo_root: PathBuf,
    metadata_commit: String,
    author: String,
    date: String,
    limits: crate::SourceLimits,
    paths: Option<std::vec::IntoIter<String>>,
    stopped: bool,
}

impl UntrackedWorktreeChunks {
    fn new(
        repo_arg: String,
        repo_root: PathBuf,
        metadata_commit: String,
        author: String,
        date: String,
        limits: crate::SourceLimits,
    ) -> Self {
        Self {
            repo_arg,
            repo_root,
            metadata_commit,
            author,
            date,
            limits,
            paths: None,
            stopped: false,
        }
    }

    fn next_row(
        &mut self,
        total_bytes: &mut usize,
        chunk_count: &mut usize,
        aggregate_cap_reported: &mut bool,
    ) -> Result<Option<Result<Chunk, SourceError>>, SourceError> {
        if self.stopped {
            return Ok(None);
        }
        if self.paths.is_none() {
            self.paths =
                Some(list_untracked_worktree_paths(&self.repo_arg, self.limits)?.into_iter());
        }
        let Some(paths) = self.paths.as_mut() else {
            return Err(SourceError::Other(
                "git-diff untracked path iterator failed to initialize".into(),
            ));
        };
        while let Some(rel) = paths.next() {
            if let Some(cap) =
                super::git_history_cap_status(*total_bytes, *chunk_count, self.limits)
            {
                if let Some(error) = super::record_git_cap_once(
                    cap,
                    aggregate_cap_reported,
                    "git diff source",
                    "remaining changed lines",
                ) {
                    self.stopped = true;
                    return Ok(Some(Err(error)));
                }
                self.stopped = true;
                return Ok(None);
            }
            match read_untracked_worktree_chunk(
                &self.repo_root,
                &rel,
                &self.metadata_commit,
                &self.author,
                &self.date,
                self.limits,
            ) {
                Ok(Some(chunk)) => {
                    *total_bytes = total_bytes.saturating_add(chunk.data.as_ref().len());
                    *chunk_count = chunk_count.saturating_add(1);
                    return Ok(Some(Ok(chunk)));
                }
                Ok(None) => {}
                Err(error) => return Ok(Some(Err(error))),
            }
        }
        Ok(None)
    }
}

fn list_untracked_worktree_paths(
    repo_arg: &str,
    limits: crate::SourceLimits,
) -> Result<Vec<String>, SourceError> {
    let mut command = Command::new(super::git_bin()?);
    command.args([
        "-C",
        repo_arg,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
    ]);
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = super::spawn_git_child(command)?;
    let mut stdout = child
        .take_stdout()
        .ok_or_else(|| SourceError::Io(std::io::Error::other("missing ls-files stdout")))?;
    let mut raw_paths: Vec<Vec<u8>> = Vec::new();
    let mut path_buf = Vec::new();
    let mut read_buf = [0_u8; 8192];
    let mut overlong_path = false;
    let mut saw_overlong_path = false;
    loop {
        let read = stdout.read(&mut read_buf).map_err(SourceError::Io)?;
        if read == 0 {
            break;
        }
        for byte in &read_buf[..read] {
            if *byte == 0 {
                if !path_buf.is_empty() && !overlong_path {
                    raw_paths.push(std::mem::take(&mut path_buf));
                } else {
                    path_buf.clear();
                }
                saw_overlong_path |= overlong_path;
                overlong_path = false;
                continue;
            }
            if path_buf.len() < limits.git_line_bytes {
                path_buf.push(*byte);
            } else {
                overlong_path = true;
                saw_overlong_path = true;
            }
        }
    }
    if !path_buf.is_empty() {
        if overlong_path {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
            super::wait_for_git_child(
                &mut child,
                "git ls-files --others",
                "enumerating untracked paths",
            )?;
            return Err(SourceError::Git(format!(
                "git ls-files reported an untracked path longer than git_line_bytes ({})",
                limits.git_line_bytes
            )));
        }
        raw_paths.push(path_buf);
    }
    if saw_overlong_path {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
        super::wait_for_git_child(
            &mut child,
            "git ls-files --others",
            "enumerating untracked paths",
        )?;
        return Err(SourceError::Git(format!(
            "git ls-files reported an untracked path longer than git_line_bytes ({})",
            limits.git_line_bytes
        )));
    }
    super::wait_for_git_child(
        &mut child,
        "git ls-files --others",
        "enumerating untracked paths",
    )?;

    let mut paths = Vec::new();
    for raw in raw_paths {
        let rel = std::str::from_utf8(&raw).map_err(|error| {
            SourceError::Git(format!("git reported non-UTF-8 untracked path: {error}"))
        })?;
        validate_untracked_relative_path(rel)?;
        paths.push(rel.to_string());
    }
    Ok(paths)
}

fn read_untracked_worktree_chunk(
    repo_root: &Path,
    rel: &str,
    metadata_commit: &str,
    author: &str,
    date: &str,
    limits: crate::SourceLimits,
) -> Result<Option<Chunk>, SourceError> {
    validate_untracked_relative_path(rel)?;
    let full_path = repo_root.join(rel);
    let metadata = std::fs::symlink_metadata(&full_path).map_err(SourceError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(SourceError::Git(format!(
            "git-diff untracked path '{}' is not a regular file",
            rel
        )));
    }
    if metadata.len() > limits.git_blob_bytes {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return Err(SourceError::Git(format!(
            "git-diff untracked path '{}' exceeds git_blob_bytes limit ({} > {})",
            rel,
            metadata.len(),
            limits.git_blob_bytes
        )));
    }
    let file = crate::filesystem::open_file_safe(&full_path).map_err(SourceError::Io)?;
    let read = crate::capped_read::read_to_cap(file, limits.git_blob_bytes, Some(metadata.len()))
        .map_err(SourceError::Io)?;
    if read.truncated {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return Err(SourceError::Git(format!(
            "git-diff untracked path '{}' grew beyond git_blob_bytes limit while reading",
            rel
        )));
    }
    let Some(text) = crate::filesystem::decode_text_file(&read.bytes) else {
        eprintln!(
            "keyhog: WARNING: git-diff untracked path '{}' decoded as binary/non-text; it was NOT scanned.",
            rel
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
        return Ok(None);
    };
    if text.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "git-diff".into(),
            path: Some(rel.to_string()),
            commit: Some(metadata_commit.to_string()),
            author: Some(author.to_string()),
            date: Some(date.to_string()),
            mtime_ns: None,
            size_bytes: Some(metadata.len()),
            decoded_span: None,
        },
    }))
}

fn validate_untracked_relative_path(path: &str) -> Result<(), SourceError> {
    let path = Path::new(path);
    if path.is_absolute() {
        return Err(SourceError::Git(
            "git reported absolute untracked path for git-diff".into(),
        ));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(SourceError::Git(
            "git reported unsafe untracked path for git-diff".into(),
        ));
    }
    Ok(())
}
