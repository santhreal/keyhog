//! Git history source: scans all commits in a repository's history for secrets
//! that may have been committed and later removed.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

/// Scans git history commit-by-commit using patch output and extracts added lines.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::Source;
/// use keyhog_sources::GitHistorySource;
/// use std::path::PathBuf;
///
/// let source = GitHistorySource::new(PathBuf::from(".")).with_max_commits(25);
/// assert_eq!(source.name(), "git-history");
/// ```
pub struct GitHistorySource {
    repo_path: PathBuf,
    pub(crate) max_commits: Option<usize>,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
}

impl GitHistorySource {
    /// Create a source that scans commit history patches for added lines.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::GitHistorySource;
    /// use std::path::PathBuf;
    ///
    /// let source = GitHistorySource::new(PathBuf::from("."));
    /// assert_eq!(source.name(), "git-history");
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
    /// use keyhog_sources::GitHistorySource;
    /// use std::path::PathBuf;
    ///
    /// let source = GitHistorySource::new(PathBuf::from(".")).with_max_commits(2);
    /// assert_eq!(source.name(), "git-history");
    /// ```
    pub fn with_max_commits(mut self, n: usize) -> Self {
        // Single owner of the commit-cap conversion lives in `source.rs`; both
        // git builders route through it so the byte-identical setters cannot
        // drift (e.g. if a clamp/normalize policy is ever added).
        self.max_commits = super::source::max_commits_limit(n);
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

impl Source for GitHistorySource {
    fn name(&self) -> &str {
        "git-history"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        crate::gate_scan(|| {
            match stream_git_history_chunks(
                &self.repo_path,
                self.max_commits,
                self.limits,
                self.respect_default_excludes,
            ) {
                Ok(iter) => Box::new(iter),
                Err(error) => Box::new(std::iter::once(Err(error))),
            }
        })
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn stream_git_history_chunks(
    repo_path: &Path,
    max_commits: Option<usize>,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
) -> Result<impl Iterator<Item = Result<Chunk, SourceError>>, SourceError> {
    let repo_arg = super::validate_repo_path(repo_path)?;
    let mut command = super::git_command()?;
    command.args([
        "-C",
        &repo_arg,
        "log",
        "--date=iso-strict",
        "--format=commit %H%nAuthor: %an <%ae>%nDate: %aI",
        "-p",
        "-m",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        // Zero context so each hunk's `+` lines are the contiguous new-file
        // run starting at the header's `+new_start`: lets a single per-hunk
        // `base_line` map every added line to its absolute new-file line.
        // Context lines were already discarded (only `+` lines are collected),
        // so -U0 changes nothing about what is scanned, only the line math.
        "-U0",
    ]);

    if let Some(limit) = max_commits {
        command.args(["--max-count", &limit.to_string()]);
    }

    command.arg("--end-of-options");
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = super::spawn_git_child(command)?;
    let stdout = child
        .take_stdout()
        .ok_or_else(|| SourceError::Io(std::io::Error::other("missing stdout")))?;
    let mut reader = std::io::BufReader::new(stdout);

    let mut current_commit: Option<String> = None;
    let mut current_author: Option<String> = None;
    let mut current_date: Option<String> = None;
    let mut current_path: Option<String> = None;
    let mut current_content = Vec::new();
    let mut diff_parser = super::UnifiedDiffParser::new();
    let mut done = false;
    let mut wait_after_final_chunk = false;
    let mut pending_errors: VecDeque<SourceError> = VecDeque::new();
    let mut line_buf = Vec::new();
    let hunk_byte_cap = super::git_blob_bytes_limit_usize(limits);
    let mut total_bytes = 0usize;
    let mut chunk_count = 0usize;
    let mut aggregate_cap_reported = false;
    // New-file line before the current hunk's first added line (hunk header
    // `+new_start - 1`). Added to a match's chunk-local line so findings
    // report the absolute new-file line instead of the chunk-local one
    // (every history finding was otherwise reported at line 1). Each hunk is
    // emitted as its own chunk so its base applies cleanly.
    let mut current_base_line: usize = 0;

    Ok(std::iter::from_fn(move || {
        if wait_after_final_chunk {
            wait_after_final_chunk = false;
            done = true;
            return super::wait_for_git_child(&mut child, "git log", "enumerating git patches")
                .err()
                .map(Err);
        }
        if done {
            return None;
        }
        if let Some(error) = pending_errors.pop_front() {
            return Some(Err(error));
        }
        if let Some(cap) = super::git_history_cap_status(total_bytes, chunk_count, limits) {
            let error = super::record_git_history_cap_once(cap, &mut aggregate_cap_reported);
            done = true;
            return error.map(Err);
        }

        loop {
            line_buf.clear();
            let line =
                match super::read_capped_line(&mut reader, &mut line_buf, limits.git_line_bytes) {
                    Ok(n) if n > limits.git_line_bytes => {
                        return Some(Err(super::git_output_line_truncated_error(
                            "git history source",
                            "unified diff line",
                            limits.git_line_bytes,
                            n,
                        )));
                    }
                    Ok(0) => {
                        if let (Some(commit), Some(author), Some(date), Some(path)) = (
                            &current_commit,
                            &current_author,
                            &current_date,
                            &current_path,
                        ) {
                            if let Some(chunk_content) =
                                super::drain_trimmed_hunk(&mut current_content)
                            {
                                wait_after_final_chunk = true;
                                return Some(Ok(make_git_history_chunk(
                                    chunk_content,
                                    current_base_line,
                                    path,
                                    commit,
                                    author,
                                    date,
                                    &mut total_bytes,
                                    &mut chunk_count,
                                )));
                            }
                        }
                        done = true;
                        return super::wait_for_git_child(
                            &mut child,
                            "git log",
                            "enumerating git patches",
                        )
                        .err()
                        .map(Err);
                    }
                    Ok(_) => super::trim_diff_line_bytes(&line_buf),
                    Err(e) => {
                        done = true;
                        return Some(Err(SourceError::Io(e)));
                    }
                };

            if let Some(commit) = line.strip_prefix(b"commit ") {
                let prev_chunk = if let (Some(commit), Some(author), Some(date), Some(path)) = (
                    &current_commit,
                    &current_author,
                    &current_date,
                    &current_path,
                ) {
                    super::drain_trimmed_hunk(&mut current_content).map(|chunk_content| {
                        make_git_history_chunk(
                            chunk_content,
                            current_base_line,
                            path,
                            commit,
                            author,
                            date,
                            &mut total_bytes,
                            &mut chunk_count,
                        )
                    })
                } else {
                    None
                };

                current_commit = Some(String::from_utf8_lossy(commit).trim().to_string());
                current_author = None;
                current_date = None;
                current_path = None;
                current_content.clear();
                diff_parser = super::UnifiedDiffParser::new();
                // New commit/file: the next `@@` sets the base for its hunks.
                current_base_line = 0;

                if let Some(chunk) = prev_chunk {
                    return Some(Ok(chunk));
                }
                continue;
            }

            if let Some(author) = line.strip_prefix(b"Author: ") {
                current_author = Some(String::from_utf8_lossy(author).trim().to_string());
                continue;
            }

            if let Some(date) = line.strip_prefix(b"Date: ") {
                current_date = Some(String::from_utf8_lossy(date).trim().to_string());
                continue;
            }

            let event = match diff_parser.parse_line(line, "git log") {
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
                    let prev_chunk = if let (Some(commit), Some(author), Some(date), Some(path)) = (
                        &current_commit,
                        &current_author,
                        &current_date,
                        &current_path,
                    ) {
                        super::drain_trimmed_hunk(&mut current_content).map(|chunk_content| {
                            make_git_history_chunk(
                                chunk_content,
                                current_base_line,
                                path,
                                commit,
                                author,
                                date,
                                &mut total_bytes,
                                &mut chunk_count,
                            )
                        })
                    } else {
                        None
                    };

                    if invalid_path {
                        tracing::warn!(
                            "git history file header path failed sanitization; added lines for that file were NOT scanned"
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                        pending_errors.push_back(SourceError::Other(
                            "git history file header path failed sanitization; added lines for that file were NOT scanned"
                                .into(),
                        ));
                    }
                    current_path = match new_path {
                        Some(path)
                            if respect_default_excludes
                                && crate::filesystem::is_default_excluded_path(&path) =>
                        {
                            let _event = crate::record_skip_event(crate::SourceSkipEvent::Excluded);
                            None
                        }
                        path => path,
                    };
                    current_content.clear();
                    // New commit/file: the next `@@` sets the base for its hunks.
                    current_base_line = 0;

                    if let Some(chunk) = prev_chunk {
                        return Some(Ok(chunk));
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
                    // New hunk: flush the previous hunk's added lines as their own
                    // chunk (carrying their base line), then adopt this hunk's
                    // new-file start for the lines that follow.
                    let prev_content = super::drain_trimmed_hunk(&mut current_content);
                    let prev_base_line = current_base_line;
                    current_base_line = base_line;
                    if let (Some(commit), Some(author), Some(date), Some(path)) = (
                        &current_commit,
                        &current_author,
                        &current_date,
                        &current_path,
                    ) {
                        if let Some(prev_content) = prev_content {
                            return Some(Ok(make_git_history_chunk(
                                prev_content,
                                prev_base_line,
                                path,
                                commit,
                                author,
                                date,
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

            // Safety cap to prevent unlimited memory growth per file hunk.
            if current_content.len() > hunk_byte_cap {
                if let (Some(commit), Some(author), Some(date), Some(path)) = (
                    &current_commit,
                    &current_author,
                    &current_date,
                    &current_path,
                ) {
                    let emitted_lines = memchr::memchr_iter(b'\n', &current_content).count();
                    if let Some(chunk_content) = super::drain_trimmed_hunk(&mut current_content) {
                        let flush_base_line = current_base_line;
                        // Mid-hunk flush of a single over-cap hunk: advance the base
                        // by the lines emitted now so the remaining lines of the
                        // SAME hunk stay correctly attributed after the reset.
                        current_base_line = current_base_line.saturating_add(emitted_lines);
                        return Some(Ok(make_git_history_chunk(
                            chunk_content,
                            flush_base_line,
                            path,
                            commit,
                            author,
                            date,
                            &mut total_bytes,
                            &mut chunk_count,
                        )));
                    }
                }
            }
        }
    }))
}

fn make_git_history_chunk(
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
            source_type: "git-history".into(),
            path: Some(path.into()),
            commit: Some(commit.into()),
            author: Some(author.into()),
            date: Some(date.into()),
            mtime_ns: None,
            size_bytes: None,
            decoded_span: None,
        },
    }
}
