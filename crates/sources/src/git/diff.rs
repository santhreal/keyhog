//! Git diff source: scans only added/modified lines from `git diff`, ideal for
//! CI/CD pre-commit hooks that should only flag new secrets.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
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

    // Verify the refs exist first
    super::verify_ref(&repo_arg, &base_ref)?;
    let base_commit = super::get_commit_hash(&repo_arg, &base_ref)?;
    let head_commit = if let Some(head_ref) = head_ref.as_deref() {
        super::verify_ref(&repo_arg, head_ref)?;
        Some(super::get_commit_hash(&repo_arg, head_ref)?)
    } else {
        None
    };

    // Run git diff to get unified diff output
    let mut command = Command::new(super::git_bin()?);
    command.args(["-C", &repo_arg, "diff", "-U0", "--end-of-options"]);
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
    let author = super::get_commit_author(&repo_arg, &metadata_commit)?;
    let date = super::get_commit_date(&repo_arg, &metadata_commit)?;
    let mut untracked_chunks = if head_ref.is_none() {
        list_untracked_worktree_chunks(
            &repo_arg,
            &repo_root,
            &metadata_commit,
            &author,
            &date,
            limits,
        )?
    } else {
        Vec::new()
    }
    .into_iter();

    let mut current_path: Option<String> = None;
    let mut current_content = String::new();
    let mut in_hunk = false;
    let mut done = false;
    let mut emit_untracked = false;
    let mut wait_after_final_chunk = false;
    let mut line_buf: Vec<u8> = Vec::new();
    let hunk_byte_cap = super::git_blob_bytes_limit_usize(limits);
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
        if emit_untracked {
            match untracked_chunks.next() {
                Some(chunk) => return Some(Ok(chunk)),
                None => {
                    done = true;
                    return None;
                }
            }
        }
        if done {
            return None;
        }

        loop {
            let line =
                match super::read_capped_line(&mut reader, &mut line_buf, limits.git_line_bytes) {
                    Ok(n) if n > 0 => {
                        let l = String::from_utf8_lossy(&line_buf);
                        l.trim_end_matches('\n').trim_end_matches('\r').to_string()
                    }
                    Err(e) => {
                        done = true;
                        return Some(Err(SourceError::Io(e)));
                    }
                    Ok(_) => {
                        if let Some(ref path) = current_path {
                            if !current_content.trim().is_empty() {
                                wait_after_final_chunk = true;
                                return Some(Ok(Chunk {
                                    data: current_content.trim().to_string().into(),
                                    metadata: ChunkMetadata {
                                        base_offset: 0,
                                        base_line: current_base_line,
                                        source_type: "git-diff".into(),
                                        path: Some(path.clone()),
                                        commit: Some(metadata_commit.clone()),
                                        author: Some(author.clone()),
                                        date: Some(date.clone()),
                                        mtime_ns: None,
                                        size_bytes: None,
                                        decoded_span: None,
                                    },
                                }));
                            }
                        }
                        match super::wait_for_git_child(
                            &mut child,
                            "git diff",
                            "enumerating changed lines",
                        ) {
                            Ok(()) => {
                                emit_untracked = true;
                                return untracked_chunks.next().map(Ok);
                            }
                            Err(error) => {
                                done = true;
                                return Some(Err(error));
                            }
                        }
                    }
                };

            if line.starts_with("diff --git ") {
                let prev_path = current_path.take();
                let prev_content = std::mem::take(&mut current_content);
                let prev_base_line = current_base_line;

                in_hunk = false;
                // New file: its first `@@` will set the base for its hunks.
                current_base_line = 0;

                if let Some(path) = prev_path {
                    if !prev_content.trim().is_empty() {
                        return Some(Ok(Chunk {
                            data: prev_content.trim().to_string().into(),
                            metadata: ChunkMetadata {
                                base_offset: 0,
                                base_line: prev_base_line,
                                source_type: "git-diff".into(),
                                path: Some(path),
                                commit: Some(metadata_commit.clone()),
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
                // Start of a new hunk: flush the previous hunk as its own
                // chunk (so its base line applies cleanly), then adopt this
                // hunk's new-file start as the base for the lines that follow.
                let new_start = match super::parse_hunk_new_start_or_error(&line, "git diff") {
                    Ok(new_start) => new_start,
                    Err(error) => {
                        done = true;
                        return Some(Err(error));
                    }
                };
                let prev_content = std::mem::take(&mut current_content);
                let prev_base_line = current_base_line;
                current_base_line = new_start.saturating_sub(1);
                in_hunk = true;
                if let Some(ref path) = current_path {
                    if !prev_content.trim().is_empty() {
                        return Some(Ok(Chunk {
                            data: prev_content.trim().to_string().into(),
                            metadata: ChunkMetadata {
                                base_offset: 0,
                                base_line: prev_base_line,
                                source_type: "git-diff".into(),
                                path: Some(path.clone()),
                                commit: Some(metadata_commit.clone()),
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

            if in_hunk && line.starts_with('+') && !line.starts_with("+++") {
                current_content.push_str(&line[1..]);
                current_content.push('\n');
            }

            if current_content.len() > hunk_byte_cap {
                if let Some(ref path) = current_path {
                    if !current_content.trim().is_empty() {
                        let flush_base_line = current_base_line;
                        // Mid-hunk flush of a single over-cap hunk: the lines
                        // that follow continue the SAME hunk, so advance the
                        // base by the lines we are emitting now to keep their
                        // attribution correct after the buffer resets.
                        current_base_line = current_base_line.saturating_add(
                            memchr::memchr_iter(b'\n', current_content.as_bytes()).count(),
                        );
                        let chunk_content = current_content.trim().to_string();
                        current_content = String::new();
                        return Some(Ok(Chunk {
                            data: chunk_content.into(),
                            metadata: ChunkMetadata {
                                base_offset: 0,
                                base_line: flush_base_line,
                                source_type: "git-diff".into(),
                                path: Some(path.clone()),
                                commit: Some(metadata_commit.clone()),
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
        }
    }))
}

fn list_untracked_worktree_chunks(
    repo_arg: &str,
    repo_root: &Path,
    metadata_commit: &str,
    author: &str,
    date: &str,
    limits: crate::SourceLimits,
) -> Result<Vec<Chunk>, SourceError> {
    let output = Command::new(super::git_bin()?)
        .args([
            "-C",
            repo_arg,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
        ])
        .output()
        .map_err(SourceError::Io)?;
    if !output.status.success() {
        return Err(SourceError::Git(format!(
            "git ls-files --others failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let mut chunks = Vec::new();
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        let rel = std::str::from_utf8(raw).map_err(|error| {
            SourceError::Git(format!("git reported non-UTF-8 untracked path: {error}"))
        })?;
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
            return Err(SourceError::Git(format!(
                "git-diff untracked path '{}' exceeds git_blob_bytes limit ({} > {})",
                rel,
                metadata.len(),
                limits.git_blob_bytes
            )));
        }
        let mut file = std::fs::File::open(&full_path).map_err(SourceError::Io)?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(limits.git_blob_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(SourceError::Io)?;
        if bytes.len() as u64 > limits.git_blob_bytes {
            return Err(SourceError::Git(format!(
                "git-diff untracked path '{}' grew beyond git_blob_bytes limit while reading",
                rel
            )));
        }
        let Some(text) = crate::filesystem::decode_text_file(&bytes) else {
            eprintln!(
                "keyhog: WARNING: git-diff untracked path '{}' decoded as binary/non-text; it was NOT scanned.",
                rel
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }
        chunks.push(Chunk {
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
        });
    }
    Ok(chunks)
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
