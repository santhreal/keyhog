//! Git diff source: scans only added/modified lines from `git diff`, ideal for
//! CI/CD pre-commit hooks that should only flag new secrets.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::io::BufRead;
use std::path::{Path, PathBuf};
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
}

impl Source for GitDiffSource {
    fn name(&self) -> &str {
        "git-diff"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match stream_added_lines(&self.repo_path, &self.base_ref, self.head_ref.as_deref()) {
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
) -> Result<impl Iterator<Item = Result<Chunk, SourceError>>, SourceError> {
    let base_ref = super::validate_ref_name(base_ref)?;
    let head_ref = super::validate_ref_name(head_ref.unwrap_or("HEAD"))?;
    let repo_root = super::canonical_repo_root(repo_path)?;
    let repo_arg = super::validate_repo_path(&repo_root)?;

    // Verify the refs exist first
    super::verify_ref(&repo_arg, &base_ref)?;
    super::verify_ref(&repo_arg, &head_ref)?;
    let base_commit = super::get_commit_hash(&repo_arg, &base_ref)?;
    let head_commit = super::get_commit_hash(&repo_arg, &head_ref)?;

    // Run git diff to get unified diff output
    let mut command = Command::new(super::git_bin()?);
    command.args([
        "-C",
        &repo_arg,
        "diff",
        "-U0",
        "--end-of-options",
        &base_commit,
        &head_commit,
    ]);

    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = command.spawn().map_err(SourceError::Io)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SourceError::Io(std::io::Error::other("missing stdout")))?;
    let mut reader = std::io::BufReader::new(stdout).lines();

    // Get commit info for metadata
    let author = super::get_commit_author(&repo_arg, &head_commit)?;
    let date = super::get_commit_date(&repo_arg, &head_commit)?;

    let mut current_path: Option<String> = None;
    let mut current_content = String::new();
    let mut in_hunk = false;
    let mut done = false;

    Ok(std::iter::from_fn(move || {
        if done {
            return None;
        }

        loop {
            let line = match reader.next() {
                Some(Ok(l)) => l,
                Some(Err(e)) => {
                    done = true;
                    return Some(Err(SourceError::Io(e)));
                }
                None => {
                    done = true;
                    if let Some(ref path) = current_path {
                        if !current_content.trim().is_empty() {
                            return Some(Ok(Chunk {
                                data: current_content.trim().to_string().into(),
                                metadata: ChunkMetadata {
                    base_offset: 0,
                                    source_type: "git-diff".into(),
                                    path: Some(path.clone()),
                                    commit: Some(head_commit.clone()),
                                    author: Some(author.clone()),
                                    date: Some(date.clone()),
                                },
                            }));
                        }
                    }
                    return None;
                }
            };

            if line.starts_with("diff --git ") {
                let prev_path = current_path.take();
                let prev_content = std::mem::take(&mut current_content);

                in_hunk = false;

                if let Some(path) = prev_path {
                    if !prev_content.trim().is_empty() {
                        return Some(Ok(Chunk {
                            data: prev_content.trim().to_string().into(),
                            metadata: ChunkMetadata {
                    base_offset: 0,
                                source_type: "git-diff".into(),
                                path: Some(path),
                                commit: Some(head_commit.clone()),
                                author: Some(author.clone()),
                                date: Some(date.clone()),
                            },
                        }));
                    }
                }
                continue;
            }

            if line.starts_with("deleted file mode") {
                current_path = None;
                continue;
            }

            if line.starts_with("new file mode")
                || line.starts_with("index ")
                || line.starts_with("--- ")
            {
                continue;
            }

            if let Some(path_part) = line.strip_prefix("+++ b/") {
                current_path = Some(path_part.trim().to_string());
                continue;
            }

            if line.starts_with("@@") && line.contains("@@") {
                in_hunk = true;
                continue;
            }

            if in_hunk && line.starts_with('+') && !line.starts_with("+++") {
                current_content.push_str(&line[1..]);
                current_content.push('\n');
            }

            if current_content.len() > 10 * 1024 * 1024 {
                if let Some(ref path) = current_path {
                    if !current_content.trim().is_empty() {
                        let chunk_content = current_content.trim().to_string();
                        current_content = String::new();
                        return Some(Ok(Chunk {
                            data: chunk_content.into(),
                            metadata: ChunkMetadata {
                    base_offset: 0,
                                source_type: "git-diff".into(),
                                path: Some(path.clone()),
                                commit: Some(head_commit.clone()),
                                author: Some(author.clone()),
                                date: Some(date.clone()),
                            },
                        }));
                    }
                }
            }
        }
    }))
}
