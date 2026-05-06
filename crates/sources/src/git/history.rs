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
}

impl Source for GitHistorySource {
    fn name(&self) -> &str {
        "git-history"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match stream_git_history_chunks(&self.repo_path, self.max_commits) {
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

    Ok(std::iter::from_fn(move || {
        if done {
            return None;
        }

        loop {
            line_buf.clear();
            let line = match std::io::BufRead::read_until(&mut reader, b'\n', &mut line_buf) {
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
                                    source_type: "git-history".into(),
                                    path: Some(path.clone()),
                                    commit: Some(commit.clone()),
                                    author: Some(author.clone()),
                                    date: Some(date.clone()),
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
                                source_type: "git-history".into(),
                                path: Some(path.clone()),
                                commit: Some(commit.clone()),
                                author: Some(author.clone()),
                                date: Some(date.clone()),
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
                                source_type: "git-history".into(),
                                path: Some(path.clone()),
                                commit: Some(commit.clone()),
                                author: Some(author.clone()),
                                date: Some(date.clone()),
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
                in_hunk = true;
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
                    let chunk_content = current_content.trim().to_string();
                    current_content.clear();
                    return Some(Ok(Chunk {
                        data: chunk_content.into(),
                        metadata: ChunkMetadata {
                            base_offset: 0,
                            source_type: "git-history".into(),
                            path: Some(path.clone()),
                            commit: Some(commit.clone()),
                            author: Some(author.clone()),
                            date: Some(date.clone()),
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
