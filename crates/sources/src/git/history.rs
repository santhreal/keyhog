//! Git history source: scans all commits in a repository's history for secrets
//! that may have been committed and later removed.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::path::{Path, PathBuf};
use std::process::Command;

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
    max_commits: Option<usize>,
    limits: crate::SourceLimits,
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
        self.max_commits = Some(n);
        self
    }

    pub fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl Source for GitHistorySource {
    fn name(&self) -> &str {
        "git-history"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match stream_git_history_chunks(&self.repo_path, self.max_commits, self.limits) {
            Ok(iter) => Box::new(iter),
            Err(error) => Box::new(std::iter::once(Err(error))),
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn stream_git_history_chunks(
    repo_path: &Path,
    max_commits: Option<usize>,
    limits: crate::SourceLimits,
) -> Result<impl Iterator<Item = Result<Chunk, SourceError>>, SourceError> {
    let repo_arg = super::validate_repo_path(repo_path)?;
    let mut command = Command::new(super::git_bin()?);
    command.args([
        "-C",
        &repo_arg,
        "log",
        "--date=iso-strict",
        "--format=commit %H%nAuthor: %an <%ae>%nDate: %aI",
        "-p",
        "-m",
        // Zero context so each hunk's `+` lines are the contiguous new-file
        // run starting at the header's `+new_start` — lets a single per-hunk
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

    let mut child = command.spawn().map_err(SourceError::Io)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SourceError::Io(std::io::Error::other("missing stdout")))?;
    let mut reader = std::io::BufReader::new(stdout);

    let mut current_commit: Option<String> = None;
    let mut current_author: Option<String> = None;
    let mut current_date: Option<String> = None;
    let mut current_path: Option<String> = None;
    let mut current_content = String::new();
    let mut in_hunk = false;
    let mut done = false;
    let mut line_buf = Vec::new();
    // New-file line before the current hunk's first added line (hunk header
    // `+new_start - 1`). Added to a match's chunk-local line so findings
    // report the absolute new-file line instead of the chunk-local one
    // (every history finding was otherwise reported at line 1). Each hunk is
    // emitted as its own chunk so its base applies cleanly.
    let mut current_base_line: usize = 0;

    Ok(std::iter::from_fn(move || {
        if done {
            return None;
        }

        loop {
            line_buf.clear();
            let line =
                match super::read_capped_line(&mut reader, &mut line_buf, limits.git_line_bytes) {
                    Ok(0) => {
                        done = true;
                        if let (Some(commit), Some(author), Some(date), Some(path)) = (
                            &current_commit,
                            &current_author,
                            &current_date,
                            &current_path,
                        ) {
                            if !current_content.trim().is_empty() {
                                return Some(Ok(Chunk {
                                    data: current_content.trim().to_string().into(),
                                    metadata: ChunkMetadata {
                                        base_offset: 0,
                                        base_line: current_base_line,
                                        source_type: "git-history".into(),
                                        path: Some(path.clone()),
                                        commit: Some(commit.clone()),
                                        author: Some(author.clone()),
                                        date: Some(date.clone()),
                                        mtime_ns: None,
                                        size_bytes: None,
                                        decoded_span: None,
                                    },
                                }));
                            }
                        }
                        return None;
                    }
                    Ok(_) => {
                        let l = String::from_utf8_lossy(&line_buf);
                        l.trim_end_matches('\n').trim_end_matches('\r').to_string()
                    }
                    Err(e) => {
                        done = true;
                        return Some(Err(SourceError::Io(e)));
                    }
                };

            if let Some(commit) = line.strip_prefix("commit ") {
                let prev_chunk = if let (Some(commit), Some(author), Some(date), Some(path)) = (
                    &current_commit,
                    &current_author,
                    &current_date,
                    &current_path,
                ) {
                    if !current_content.trim().is_empty() {
                        Some(Chunk {
                            data: current_content.trim().to_string().into(),
                            metadata: ChunkMetadata {
                                base_offset: 0,
                                base_line: current_base_line,
                                source_type: "git-history".into(),
                                path: Some(path.clone()),
                                commit: Some(commit.clone()),
                                author: Some(author.clone()),
                                date: Some(date.clone()),
                                mtime_ns: None,
                                size_bytes: None,
                                decoded_span: None,
                            },
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };

                current_commit = Some(commit.trim().to_string());
                current_author = None;
                current_date = None;
                current_path = None;
                current_content.clear();
                in_hunk = false;
                // New commit/file: the next `@@` sets the base for its hunks.
                current_base_line = 0;

                if let Some(chunk) = prev_chunk {
                    return Some(Ok(chunk));
                }
                continue;
            }

            if let Some(author) = line.strip_prefix("Author: ") {
                current_author = Some(author.trim().to_string());
                continue;
            }

            if let Some(date) = line.strip_prefix("Date: ") {
                current_date = Some(date.trim().to_string());
                continue;
            }

            if line.starts_with("diff --git ") {
                let prev_chunk = if let (Some(commit), Some(author), Some(date), Some(path)) = (
                    &current_commit,
                    &current_author,
                    &current_date,
                    &current_path,
                ) {
                    if !current_content.trim().is_empty() {
                        Some(Chunk {
                            data: current_content.trim().to_string().into(),
                            metadata: ChunkMetadata {
                                base_offset: 0,
                                base_line: current_base_line,
                                source_type: "git-history".into(),
                                path: Some(path.clone()),
                                commit: Some(commit.clone()),
                                author: Some(author.clone()),
                                date: Some(date.clone()),
                                mtime_ns: None,
                                size_bytes: None,
                                decoded_span: None,
                            },
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };

                current_path = extract_new_path(&line);
                current_content.clear();
                in_hunk = false;
                // New commit/file: the next `@@` sets the base for its hunks.
                current_base_line = 0;

                if let Some(chunk) = prev_chunk {
                    return Some(Ok(chunk));
                }
                continue;
            }

            if line.starts_with("new file mode")
                || line.starts_with("index ")
                || line.starts_with("--- ")
            {
                continue;
            }

            if let Some(path_part) = line.strip_prefix("+++ b/") {
                current_path = sanitize_path(path_part);
                continue;
            }

            if line.starts_with("@@") && line.contains("@@") {
                // New hunk: flush the previous hunk's added lines as their own
                // chunk (carrying their base line), then adopt this hunk's
                // new-file start for the lines that follow.
                let new_start = super::parse_hunk_new_start(&line).unwrap_or(1); // LAW10: empty/absent => documented numeric default, recall-safe
                let prev_content = std::mem::take(&mut current_content);
                let prev_base_line = current_base_line;
                current_base_line = new_start.saturating_sub(1);
                in_hunk = true;
                if let (Some(commit), Some(author), Some(date), Some(path)) = (
                    &current_commit,
                    &current_author,
                    &current_date,
                    &current_path,
                ) {
                    if !prev_content.trim().is_empty() {
                        return Some(Ok(Chunk {
                            data: prev_content.trim().to_string().into(),
                            metadata: ChunkMetadata {
                                base_offset: 0,
                                base_line: prev_base_line,
                                source_type: "git-history".into(),
                                path: Some(path.clone()),
                                commit: Some(commit.clone()),
                                author: Some(author.clone()),
                                date: Some(date.clone()),
                                mtime_ns: None,
                                size_bytes: None,
                                decoded_span: None,
                            },
                        }));
                    }
                }
                continue;
            }

            if (in_hunk || line.starts_with('+'))
                && line.starts_with('+')
                && !line.starts_with("+++")
            {
                current_content.push_str(&line[1..]);
                current_content.push('\n');
            }

            // Safety cap to prevent unlimited memory growth per file hunk
            if current_content.len() > 10 * 1024 * 1024 {
                if let (Some(commit), Some(author), Some(date), Some(path)) = (
                    &current_commit,
                    &current_author,
                    &current_date,
                    &current_path,
                ) {
                    let flush_base_line = current_base_line;
                    // Mid-hunk flush of a single >10 MiB hunk: advance the base
                    // by the lines emitted now so the remaining lines of the
                    // SAME hunk stay correctly attributed after the reset.
                    current_base_line = current_base_line.saturating_add(
                        memchr::memchr_iter(b'\n', current_content.as_bytes()).count(),
                    );
                    let chunk_content = current_content.trim().to_string();
                    current_content.clear();
                    return Some(Ok(Chunk {
                        data: chunk_content.into(),
                        metadata: ChunkMetadata {
                            base_offset: 0,
                            base_line: flush_base_line,
                            source_type: "git-history".into(),
                            path: Some(path.clone()),
                            commit: Some(commit.clone()),
                            author: Some(author.clone()),
                            date: Some(date.clone()),
                            mtime_ns: None,
                            size_bytes: None,
                            decoded_span: None,
                        },
                    }));
                }
            }
        }
    }))
}

fn extract_new_path(line: &str) -> Option<String> {
    line.find(" b/")
        .and_then(|index| sanitize_path(&line[index + 3..]))
}

fn sanitize_path(path: &str) -> Option<String> {
    let path = path.trim().replace('\\', "/");
    if path.is_empty() || path == "/dev/null" {
        return None;
    }

    let candidate = Path::new(&path);
    if candidate.is_absolute() || path.chars().any(char::is_control) {
        return None;
    }

    let mut normalized = Vec::new();
    for component in candidate.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => {
                normalized.push(part.to_string_lossy().into_owned());
            }
            std::path::Component::ParentDir => {
                normalized.pop()?;
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return None;
            }
        }
    }

    if normalized.is_empty() {
        None
    } else {
        Some(normalized.join("/"))
    }
}
