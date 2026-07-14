//! Shared git utilities.

use keyhog_core::{SourceCoverageGapKind, SourceError};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command};
use std::thread::JoinHandle;

mod diff;
mod diff_parser;
mod history;
mod source;
mod staged;
mod tag_messages;

/// Resolve `git` to an absolute path inside a trusted system bin dir.
/// SECURITY: kimi-wave1 audit finding 3.PATH-git. Refuses to fall back
/// to `Command::new("git")`, which would let a hostile $PATH substitute
/// the git binary at runtime - keyhog feeds git the repo path and
/// receives blob bytes that go through scanning, so a substituted git
/// could exfil credentials directly.
pub(crate) fn git_bin() -> Result<PathBuf, SourceError> {
    keyhog_core::resolve_safe_bin("git").ok_or_else(|| {
        SourceError::Other(
            "git binary not found in trusted system bin dirs (refusing $PATH lookup); \
             install git or add its absolute directory to [system].trusted_bin_dirs in .keyhog.toml"
                .into(),
        )
    })
}

/// Build a `git` [`Command`] with the resolved safe binary AND a hermetic
/// environment. Global/system config are nulled and terminal prompts disabled,
/// so a host `commit.gpgsign=true`, a `credential.helper`, or a `core.hooksPath`
/// cannot make a git invocation block on a passphrase / credential / hook prompt
/// (a latent CI hang; Testing-Contract HOST-INDEPENDENCE). ONE PLACE: every git
/// spawn goes through here rather than `Command::new(git_bin()?)`, so the
/// isolation set cannot drift per call site.
pub(crate) fn git_command() -> Result<Command, SourceError> {
    // Nulling the config paths disables ALL global/system config (gpgsign,
    // credential.helper, hooksPath, ...). The null device differs by platform;
    // both Git for Windows and POSIX git treat a config path pointing at it as
    // "no config".
    let null_config = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let mut command = Command::new(git_bin()?);
    command
        .env("GIT_CONFIG_GLOBAL", null_config)
        .env("GIT_CONFIG_SYSTEM", null_config)
        .env("GIT_TERMINAL_PROMPT", "0");
    Ok(command)
}

pub use diff::GitDiffSource;
pub use history::GitHistorySource;
pub use source::GitSource;
pub use staged::GitStagedSource;

pub(crate) use diff_parser::{trim_diff_line_bytes, UnifiedDiffEvent, UnifiedDiffParser};
pub(crate) use source::max_commits_limit;

/// Byte cap for a single line of git plumbing output read through
/// [`read_capped_line`].
///
/// Single owner for the fsck (`git fsck --unreachable`) and tag-ref
/// (`git for-each-ref`) readers: both bound one structurally-short metadata line
/// (an object id plus a type/refname) to the same 4 KiB ceiling, so the value
/// lives here instead of being duplicated as `GIT_FSCK_LINE_BYTES` /
/// `GIT_TAG_REF_LINE_BYTES`. (The diff/history readers scan arbitrary file
/// content and instead use the operator-configurable `limits.git_line_bytes`.)
pub(crate) const GIT_PLUMBING_LINE_BYTES: usize = 4096;

pub(crate) fn git_blob_bytes_limit_usize(limits: crate::SourceLimits) -> usize {
    match usize::try_from(limits.git_blob_bytes) {
        Ok(value) => value,
        Err(_) => usize::MAX, // LAW10: recall-safe size knob; configured cap exceeds platform usize, so saturate to the maximum representable in-memory buffer cap.
    }
}

pub(crate) fn parse_git_object_id_line(
    line: &str,
    object_label: &'static str,
) -> Option<gix::ObjectId> {
    let object_id = line.split_whitespace().next()?;
    match gix::ObjectId::from_hex(object_id.as_bytes()) {
        Ok(id) => Some(id),
        Err(error) => {
            tracing::warn!(
                %error,
                object = object_id,
                object_kind = object_label,
                "git reported an unparsable object id; object NOT scanned"
            );
            record_git_object_unreadable();
            None
        }
    }
}

pub(crate) fn record_git_object_unreadable() {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::GitObjectUnreadable);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitHistoryCap {
    TotalBytes { total: usize, cap: usize },
    Chunks { count: usize, cap: usize },
}

pub(crate) fn git_history_cap_status(
    total_bytes: usize,
    chunk_count: usize,
    limits: crate::SourceLimits,
) -> Option<GitHistoryCap> {
    if total_bytes >= limits.git_total_bytes {
        return Some(GitHistoryCap::TotalBytes {
            total: total_bytes,
            cap: limits.git_total_bytes,
        });
    }
    if chunk_count >= limits.git_chunk_count {
        return Some(GitHistoryCap::Chunks {
            count: chunk_count,
            cap: limits.git_chunk_count,
        });
    }
    None
}

pub(crate) fn record_git_history_cap_once(
    cap: GitHistoryCap,
    reported: &mut bool,
) -> Option<SourceError> {
    record_git_cap_once(cap, reported, "git history source", "remaining blobs")
}

pub(crate) fn record_git_cap_once(
    cap: GitHistoryCap,
    reported: &mut bool,
    source_name: &str,
    remaining_description: &str,
) -> Option<SourceError> {
    if *reported {
        return None;
    }
    *reported = true;
    let reason = match cap {
        GitHistoryCap::TotalBytes { total, cap } => {
            tracing::warn!(
                total_bytes = total,
                cap,
                %source_name,
                %remaining_description,
                "git source reached aggregate byte cap; remaining work was NOT scanned"
            );
            format!("aggregate byte cap reached at {total} bytes (cap {cap})")
        }
        GitHistoryCap::Chunks { count, cap } => {
            tracing::warn!(
                chunks = count,
                cap,
                %source_name,
                %remaining_description,
                "git source reached aggregate chunk cap; remaining work was NOT scanned"
            );
            format!("aggregate chunk cap reached at {count} chunk(s) (cap {cap})")
        }
    };
    let _event = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
    Some(SourceError::Coverage {
        adapter: "git".into(),
        surface: "history".into(),
        target: source_name.into(),
        kind: SourceCoverageGapKind::Truncated,
        detail: format!("{reason}; {remaining_description} were not scanned"),
    })
}

pub(crate) fn git_unscanned_object_error(reason: impl std::fmt::Display) -> SourceError {
    SourceError::Git(format!("failed to scan git object: {reason}"))
}

pub(crate) fn git_output_line_truncated_error(
    source_name: &str,
    line_kind: &str,
    cap: usize,
    consumed: usize,
) -> SourceError {
    tracing::warn!(
        %source_name,
        %line_kind,
        cap,
        consumed,
        "git output line exceeded the configured byte cap; full line was NOT scanned"
    );
    let _event = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
    SourceError::Other(format!(
        "{source_name} output was truncated: {line_kind} exceeded the {cap}-byte line cap after {consumed} bytes; the full line was not scanned"
    ))
}

pub(crate) fn drain_trimmed_hunk(buffer: &mut Vec<u8>) -> Option<String> {
    let decoded = String::from_utf8_lossy(buffer);
    let trimmed = decoded.trim();
    if trimmed.is_empty() {
        buffer.clear();
        return None;
    }
    let chunk = trimmed.to_owned();
    buffer.clear();
    Some(chunk)
}

pub(crate) struct GitChild {
    child: Child,
    stderr: Option<JoinHandle<String>>,
    waited: bool,
}

pub(crate) fn spawn_git_child(mut command: Command) -> Result<GitChild, SourceError> {
    let mut child = command.spawn().map_err(SourceError::Io)?;
    let stderr = child
        .stderr
        .take()
        .map(|pipe| std::thread::spawn(move || crate::process_excerpt::drain_stderr_excerpt(pipe)));
    Ok(GitChild {
        child,
        stderr,
        waited: false,
    })
}

impl GitChild {
    pub(crate) fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    fn wait(&mut self) -> Result<std::process::ExitStatus, SourceError> {
        let status = self.child.wait().map_err(SourceError::Io)?;
        self.waited = true;
        Ok(status)
    }

    fn stderr_excerpt(&mut self) -> String {
        match self.stderr.take() {
            Some(handle) => match handle.join() {
                Ok(stderr) => stderr,
                Err(_panic_payload) => {
                    // LAW10: stderr-reader failure is surfaced unconditionally, and child exit status still controls success/failure.
                    eprintln!(
                        "keyhog: git stderr reader panicked; stderr excerpt unavailable for child status"
                    );
                    tracing::warn!(
                        "git stderr reader panicked; stderr excerpt unavailable for child status"
                    );
                    "stderr unavailable: stderr reader panicked".to_string()
                }
            },
            None => String::new(),
        }
    }
}

impl Drop for GitChild {
    fn drop(&mut self) {
        if !self.waited {
            match self.child.try_wait() {
                Ok(Some(_status)) => {
                    self.waited = true;
                }
                Ok(None) => {
                    if let Err(error) = self.child.kill() {
                        tracing::warn!(%error, "failed to kill dropped git child");
                    }
                    match self.child.wait() {
                        Ok(_status) => {
                            self.waited = true;
                        }
                        Err(error) => {
                            tracing::warn!(%error, "failed to wait on dropped git child");
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to inspect dropped git child");
                    if let Err(kill_error) = self.child.kill() {
                        tracing::warn!(%kill_error, "failed to kill dropped git child after status error");
                    }
                    if let Err(wait_error) = self.child.wait() {
                        tracing::warn!(%wait_error, "failed to wait on dropped git child after status error");
                    } else {
                        self.waited = true;
                    }
                }
            }
        }
        if let Some(handle) = self.stderr.take() {
            if handle.join().is_err() {
                tracing::warn!("git stderr reader panicked while dropped child was being reaped");
            }
        }
    }
}

/// Read one line (through the trailing `\n`) into `buf`, capping buffered bytes
/// at `max`. If the line exceeds `max`, the first `max` bytes are kept (still
/// scanned) and the overflow is consumed and discarded so the stream stays
/// newline-aligned. Returns total bytes consumed from `reader` (0 == EOF),
/// mirroring `BufRead::read_until`'s contract so call sites branch the same.
pub(crate) fn read_capped_line<R: std::io::BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<usize> {
    read_capped_record(reader, buf, max, b'\n')
}

/// Read through one delimiter while retaining at most `max` bytes. The full
/// record is always consumed so a caller can report the oversized record and
/// continue from the next exact boundary without allocating attacker-sized
/// Git output.
pub(crate) fn read_capped_record<R: std::io::BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
    delimiter: u8,
) -> std::io::Result<usize> {
    buf.clear();
    let mut consumed = 0usize;
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok(consumed); // EOF
        }
        let boundary = memchr::memchr(delimiter, available);
        let take = boundary.map_or(available.len(), |i| i + 1);
        if buf.len() < max {
            let keep = take.min(max - buf.len());
            buf.extend_from_slice(&available[..keep]);
        }
        reader.consume(take);
        consumed += take;
        if boundary.is_some() {
            return Ok(consumed);
        }
    }
}

pub(crate) fn wait_for_git_child(
    child: &mut GitChild,
    label: &str,
    operation: &str,
) -> Result<(), SourceError> {
    let status = child.wait()?;
    let stderr = child.stderr_excerpt();
    if status.success() {
        return Ok(());
    }

    Err(SourceError::Git(format!(
        "{label} failed while {operation}: {}",
        stderr.trim()
    )))
}

pub(crate) trait GitTreeVisitor {
    fn accept_path(&mut self, _filepath: &[u8]) -> Result<bool, SourceError> {
        Ok(true)
    }

    fn visit_blob(&mut self, oid: gix::ObjectId, filepath: Vec<u8>) -> Result<(), SourceError>;

    fn handle_entry_error(&mut self, error: String) -> Result<(), SourceError>;

    fn handle_subtree_object_error(
        &mut self,
        filepath: &[u8],
        error: String,
    ) -> Result<(), SourceError>;

    fn handle_subtree_type_error(
        &mut self,
        filepath: &[u8],
        error: String,
    ) -> Result<(), SourceError>;

    fn handle_unscanned_entry(
        &mut self,
        _filepath: &[u8],
        _mode: String,
    ) -> Result<(), SourceError> {
        Ok(())
    }
}

pub(crate) fn walk_tree_recursive<V: GitTreeVisitor + ?Sized>(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
    prefix: &[u8],
    visitor: &mut V,
) -> Result<(), SourceError> {
    for entry_ref in tree.iter() {
        let entry = match entry_ref {
            Ok(entry) => entry,
            Err(error) => {
                visitor.handle_entry_error(error.to_string())?;
                continue;
            }
        };

        let oid = entry.oid().to_owned();
        let filepath = join_tree_path(prefix, entry.filename());
        if !visitor.accept_path(&filepath)? {
            continue;
        }

        let mode = entry.mode();
        if mode.is_tree() {
            let obj = match repo.find_object(oid) {
                Ok(obj) => obj,
                Err(error) => {
                    visitor.handle_subtree_object_error(&filepath, error.to_string())?;
                    continue;
                }
            };
            match obj.try_into_tree() {
                Ok(subtree) => walk_tree_recursive(repo, &subtree, &filepath, visitor)?,
                Err(error) => {
                    visitor.handle_subtree_type_error(&filepath, error.to_string())?;
                }
            }
        } else if mode.is_blob() {
            visitor.visit_blob(oid, filepath)?;
        } else {
            visitor.handle_unscanned_entry(&filepath, format!("{mode:?}"))?;
        }
    }
    Ok(())
}

fn join_tree_path(prefix: &[u8], filename: &[u8]) -> Vec<u8> {
    if prefix.is_empty() {
        filename.to_vec()
    } else {
        let mut path = Vec::with_capacity(prefix.len() + 1 + filename.len());
        path.extend_from_slice(prefix);
        path.push(b'/');
        path.extend_from_slice(filename);
        path
    }
}

#[cfg(test)]
mod plumbing_line_cap_tests {
    #[test]
    fn git_plumbing_line_cap_is_the_shared_4_kib_value() {
        // Single owner for the fsck and tag-ref line caps that previously lived as
        // two separate `GIT_FSCK_LINE_BYTES` / `GIT_TAG_REF_LINE_BYTES` constants.
        assert_eq!(super::GIT_PLUMBING_LINE_BYTES, 4096);
    }
}

#[cfg(test)]
mod capped_line_tests {
    use super::read_capped_line;
    use std::io::Cursor;

    #[test]
    fn caps_a_newlineless_blob_yet_stays_newline_aligned() {
        // A 100-byte line with no newline, then a normal line. With max=10 the
        // buffer must hold only the first 10 bytes (memory bounded) while the
        // reader still advances past the real newline so the next line is clean.
        let mut data = vec![b'x'; 100];
        data.push(b'\n');
        data.extend_from_slice(b"next\n");
        let mut r = Cursor::new(data);
        let mut buf = Vec::new();

        let n = read_capped_line(&mut r, &mut buf, 10).unwrap();
        assert_eq!(n, 101, "consumed all 100 bytes + the newline");
        assert_eq!(
            buf.len(),
            10,
            "buffered bytes capped at max despite a 100-byte line"
        );
        assert!(buf.iter().all(|&b| b == b'x'));

        let n2 = read_capped_line(&mut r, &mut buf, 10).unwrap();
        assert_eq!(n2, 5);
        assert_eq!(
            &buf[..],
            b"next\n",
            "stream stayed aligned; next line intact"
        );

        assert_eq!(read_capped_line(&mut r, &mut buf, 10).unwrap(), 0, "EOF");
    }

    #[test]
    fn yields_final_line_without_trailing_newline() {
        let mut r = Cursor::new(b"abc".to_vec());
        let mut buf = Vec::new();
        assert_eq!(read_capped_line(&mut r, &mut buf, 100).unwrap(), 3);
        assert_eq!(&buf[..], b"abc");
        assert_eq!(read_capped_line(&mut r, &mut buf, 100).unwrap(), 0);
    }
}

#[cfg(test)]
mod git_command_isolation_tests {
    use super::git_command;
    use std::process::Command;

    fn env_value(cmd: &Command, key: &str) -> Option<String> {
        cmd.get_envs()
            .find(|(k, _)| k.to_string_lossy() == key)
            .and_then(|(_, v)| v.map(|v| v.to_string_lossy().into_owned()))
    }

    /// Every git spawn must run with a hermetic environment so a host
    /// `commit.gpgsign=true`, a `credential.helper`, or a `core.hooksPath`
    /// cannot make git block on a passphrase / credential / hook prompt (a
    /// latent CI hang; Testing-Contract HOST-INDEPENDENCE). This pins the exact
    /// isolation set on the shared `git_command()` builder so no future edit can
    /// silently drop it, and so every call site inherits it via ONE PLACE.
    #[test]
    fn git_command_sets_hermetic_environment() {
        let command = match git_command() {
            Ok(c) => c,
            // git not resolvable in a trusted bin dir on this host: the whole
            // git source layer is unusable here, so there is nothing to isolate.
            // Announce the skip loudly rather than pass silently.
            Err(e) => {
                eprintln!("SKIP git_command_sets_hermetic_environment: git not resolvable ({e})");
                return;
            }
        };
        let expected_null = if cfg!(windows) { "NUL" } else { "/dev/null" };
        assert_eq!(
            env_value(&command, "GIT_CONFIG_GLOBAL").as_deref(),
            Some(expected_null),
            "global git config must be nulled to neutralize gpgsign/credential.helper/hooksPath"
        );
        assert_eq!(
            env_value(&command, "GIT_CONFIG_SYSTEM").as_deref(),
            Some(expected_null),
            "system git config must be nulled"
        );
        assert_eq!(
            env_value(&command, "GIT_TERMINAL_PROMPT").as_deref(),
            Some("0"),
            "terminal prompts must be disabled so git never blocks on a prompt"
        );
    }
}

#[cfg(test)]
mod git_child_tests {
    use super::{spawn_git_child, wait_for_git_child};
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const SPAM_STDERR_ENV: &str = "KEYHOG_TEST_SPAM_GIT_STDERR";
    const SLEEP_CHILD_ENV: &str = "KEYHOG_TEST_SLEEP_GIT_CHILD";

    #[test]
    fn streamed_git_child_drains_large_stderr_before_wait() {
        if std::env::var_os(SPAM_STDERR_ENV).is_some() {
            let payload = vec![b'E'; crate::process_excerpt::STDERR_EXCERPT_BYTES * 4];
            std::io::stderr()
                .write_all(&payload)
                .expect("child writes stderr payload");
            std::process::exit(42);
        }

        let mut command = Command::new(std::env::current_exe().expect("current test binary"));
        command
            .env(SPAM_STDERR_ENV, "1")
            .arg("--exact")
            .arg("git::git_child_tests::streamed_git_child_drains_large_stderr_before_wait")
            .arg("--nocapture")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = spawn_git_child(command).expect("spawn noisy git-child surrogate");
        let mut stdout = child.take_stdout().expect("stdout pipe");
        let mut stdout_bytes = Vec::new();
        stdout
            .read_to_end(&mut stdout_bytes)
            .expect("stdout drains after stderr reader prevents pipe deadlock");

        let error = wait_for_git_child(&mut child, "git test", "draining stderr")
            .expect_err("non-zero child exit must surface as git error");
        let message = error.to_string();
        assert!(
            message.contains("git test failed while draining stderr"),
            "expected git failure context, got {message:?}"
        );
        assert!(
            message.contains("[stderr truncated after 65536 bytes]"),
            "large stderr must be drained but stored as a bounded excerpt"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dropped_git_child_is_reaped_without_explicit_wait() {
        if std::env::var_os(SLEEP_CHILD_ENV).is_some() {
            std::thread::sleep(Duration::from_secs(120));
            std::process::exit(0);
        }

        let mut command = Command::new(std::env::current_exe().expect("current test binary"));
        command
            .env(SLEEP_CHILD_ENV, "1")
            .arg("--exact")
            .arg("git::git_child_tests::dropped_git_child_is_reaped_without_explicit_wait")
            .arg("--nocapture")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let child = spawn_git_child(command).expect("spawn sleeping git-child surrogate");
        let proc_entry = std::path::PathBuf::from(format!("/proc/{}", child.child.id()));
        assert!(
            proc_entry.exists(),
            "test child must be alive before drop so the regression is meaningful"
        );
        drop(child);

        let deadline = Instant::now() + Duration::from_secs(2);
        while proc_entry.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !proc_entry.exists(),
            "dropping GitChild must kill and wait on the subprocess so no zombie remains"
        );
    }
}

/// Parse the new-file start line from a unified-diff hunk header
/// `@@ -old_start[,old_count] +new_start[,new_count] @@ [section]`.
///
/// Returns `new_start` (1-based). The first `+` in the header is always the
/// new-side marker, so scanning to `+` and reading the following ASCII digits
/// is robust even when the trailing section text contains a `+`. Shared by the
/// diff and history sources: both run `git diff/log -U0`, where a hunk's added
/// lines are the contiguous new-file run `new_start, new_start+1, …`, so a
/// chunk built from those lines reports absolute file lines once it carries
/// `base_line = new_start - 1`.
pub(crate) fn parse_hunk_new_start_bytes(header: &[u8]) -> Option<usize> {
    let plus = memchr::memchr(b'+', header)?;
    let after_plus = &header[plus + 1..];
    let digits_end = after_plus
        .iter()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(after_plus.len()); // LAW10: hunk header digits run to end => borrowed digit slice, no error swallowed; recall-safe
    if digits_end == 0 {
        return None;
    }

    let mut value = 0usize;
    for digit in &after_plus[..digits_end] {
        value = value
            .checked_mul(10)?
            .checked_add(usize::from(digit - b'0'))?;
    }
    Some(value)
}

pub(crate) fn parse_hunk_new_start_bytes_or_error(
    header: &[u8],
    source_type: &str,
) -> Result<usize, SourceError> {
    parse_hunk_new_start_bytes(header).ok_or_else(|| {
        let header = String::from_utf8_lossy(header);
        SourceError::Other(format!(
            "{source_type} output contains malformed unified-diff hunk header {header:?}; \
             refusing to guess line 1 because that would corrupt finding line attribution"
        ))
    })
}

#[cfg(test)]
mod hunk_header_tests {
    use super::{parse_hunk_new_start_bytes, parse_hunk_new_start_bytes_or_error};

    #[test]
    fn parses_new_start_with_and_without_count() {
        assert_eq!(parse_hunk_new_start_bytes(b"@@ -1,0 +90 @@"), Some(90));
        assert_eq!(
            parse_hunk_new_start_bytes(b"@@ -10,2 +12,3 @@ fn foo()"),
            Some(12)
        );
        assert_eq!(parse_hunk_new_start_bytes(b"@@ -0,0 +1,5 @@"), Some(1));
        assert_eq!(
            parse_hunk_new_start_bytes(b"@@ -3,1 +3,1 @@ a + b"),
            Some(3)
        );
        assert_eq!(parse_hunk_new_start_bytes(b"@@ garbage @@"), None);
    }

    #[test]
    fn malformed_hunk_header_is_error_not_line_one() {
        let err = parse_hunk_new_start_bytes_or_error(b"@@ garbage @@", "git diff")
            .expect_err("malformed hunk headers must not default to line 1");
        let keyhog_core::SourceError::Other(message) = err else {
            panic!("expected SourceError::Other");
        };
        assert!(message.contains("malformed unified-diff hunk header"));
        assert!(message.contains("refusing to guess line 1"));
    }
}

pub(crate) fn validate_repo_path(repo_path: &Path) -> Result<String, SourceError> {
    // SECURITY: kimi-wave1 audit finding 3.git-source-traversal. Previously
    // this only rejected leading `-` and control chars. An attacker passing
    // `--git-blobs ../../../etc` would invoke `git -C ../../../etc log ...`,
    // reading arbitrary filesystem directories through git as if they were
    // a repo. We now canonicalize the path (resolves `..` and symlinks) and
    // require it to point at an actual `.git` directory or a worktree
    // containing one. Anything else is refused.
    // Use a lossy rendering only for validation/diagnostics; canonicalization
    // below still consumes the original OS path bytes.
    let raw = repo_path.to_string_lossy();
    if raw.starts_with('-') || raw.chars().any(char::is_control) {
        return Err(SourceError::Other(
            "repository path contains unsafe characters".into(),
        ));
    }

    let canonical = std::fs::canonicalize(repo_path).map_err(|e| {
        SourceError::Other(format!("failed to canonicalize repo path '{raw}': {e}"))
    })?;

    // Require canonical to be either a `.git` directory or a worktree whose
    // child `.git` exists. This rejects `..` traversal targets like `/etc`
    // because they don't contain a `.git`.
    let looks_like_repo = canonical.join(".git").exists()
        || canonical
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == ".git" || n.ends_with(".git"))
            && canonical.join("HEAD").exists();
    if !looks_like_repo {
        return Err(SourceError::Other(format!(
            "path '{}' is not a git repository (no .git directory or HEAD file found)",
            canonical.display()
        )));
    }

    let canonical_str = canonical
        .to_str()
        .ok_or_else(|| SourceError::Other("repo path is not valid UTF-8".into()))?;
    Ok(canonical_str.to_string())
}

pub(crate) fn canonical_repo_root(repo_path: &Path) -> Result<PathBuf, SourceError> {
    std::fs::canonicalize(repo_path).map_err(SourceError::Io)
}

pub(crate) fn validate_ref_name(ref_name: &str) -> Result<String, SourceError> {
    let ref_name = ref_name.trim();
    if ref_name.is_empty() {
        return Err(SourceError::Git("git ref cannot be empty".into()));
    }

    if ref_name.starts_with('-')
        || ref_name
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        || ref_name.contains("..")
        || ref_name.contains(':')
        || ref_name.contains('?')
        || ref_name.contains('*')
        || ref_name.contains('[')
        || ref_name.contains('\\')
    {
        return Err(SourceError::Git(format!("unsafe git ref '{ref_name}'")));
    }

    Ok(ref_name.to_string())
}

pub(crate) struct CommitMetadata {
    pub(crate) author: String,
    pub(crate) date: String,
}

pub(crate) fn resolve_commit_hash(repo_path: &str, ref_name: &str) -> Result<String, SourceError> {
    let output = git_command()?
        .args(["-C", repo_path, "rev-parse", "--verify", "--end-of-options"])
        .arg(format!("{ref_name}^{{commit}}"))
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        return Err(SourceError::Git(format!(
            "ref '{}' not found in repository",
            ref_name
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(crate) fn get_commit_metadata(
    repo_path: &str,
    ref_name: &str,
) -> Result<CommitMetadata, SourceError> {
    let output = git_command()?
        .args([
            "-C",
            repo_path,
            "log",
            "-1",
            "--format=%an%x00%aI",
            "--end-of-options",
        ])
        .arg(ref_name)
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SourceError::Git(format!(
            "failed to read commit metadata for '{}': {}",
            ref_name,
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim_end_matches(['\r', '\n']);
    let Some((author, date)) = trimmed.split_once('\0') else {
        return Err(SourceError::Git(format!(
            "git log metadata for '{}' was incomplete",
            ref_name
        )));
    };

    Ok(CommitMetadata {
        author: author.to_string(),
        date: date.to_string(),
    })
}
