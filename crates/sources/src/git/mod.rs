//! Shared git utilities.

use keyhog_core::{SourceCoverageGapKind, SourceError};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command};
use std::thread::JoinHandle;

mod diff;
mod diff_parser;
mod history;
mod manifest;
mod source;
mod staged;
mod tag_messages;
pub use manifest::{
    verify_staged_fingerprint, StagedEntryKind, StagedManifest, StagedManifestEntry,
};
pub(crate) use staged::consume_oversized_staged_header_path;
pub(crate) use source::HeadBlobPaths;

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

/// Read a staged blob's content by object ID from a repository.
/// Returns the raw blob bytes. Used by the guard commit client
/// to stream blob payloads to the daemon.
pub fn read_staged_blob(
    repo_path: &std::path::Path,
    oid: &str,
) -> Result<Vec<u8>, keyhog_core::SourceError> {
    let repo = gix::open(repo_path).map_err(|e| {
        keyhog_core::SourceError::Git(format!("failed to open repository for blob read: {e}"))
    })?;
    let object_id = gix::ObjectId::from_hex(oid.as_bytes())
        .map_err(|e| keyhog_core::SourceError::Git(format!("invalid object ID {oid}: {e}")))?;
    let object = repo
        .find_object(object_id)
        .map_err(|e| keyhog_core::SourceError::Git(format!("failed to read blob {oid}: {e}")))?;
    Ok(object.data.to_vec())
}

pub(crate) use diff_parser::{trim_diff_line_bytes, UnifiedDiffEvent, UnifiedDiffParser};
pub(crate) use source::max_commits_limit;
#[cfg(debug_assertions)]
pub(crate) use source::{max_buffered_git_blob_chunks, reset_max_buffered_git_blob_chunks};

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

/// Count the commits a SHALLOW clone is missing, and record them as a coverage
/// gap so a truncated history can never be reported as a clean scan.
///
/// `git clone --depth N` (and `actions/checkout`, which fetches one commit by
/// default) writes a `shallow` file listing the graft-boundary commits. A
/// boundary commit object still names its real parents; those parent objects
/// were simply never fetched. Every commit behind that boundary, and every
/// blob only those commits introduced, is absent from the clone. A credential
/// that was committed and later removed lives exactly there.
///
/// Before this existed, `--git-history` / `--git-blobs` on a depth-1 clone
/// exited 0 with `scan_status: success` and an EMPTY coverage-gap summary,
/// while a full clone of the same repository reported the deleted credential:
/// a structured false clean, the one outcome Law 10 forbids.
///
/// The gap is the set of PARENT ids named by boundary commits that are not in
/// the object database. That is exactly "a Git object referenced by repository
/// metadata that was not scanned", so it reuses
/// [`record_git_object_unreadable`] and needs no new category. Counting absent
/// parents rather than boundary commits also keeps the root-commit case clean:
/// `git clone --depth 1` of a single-commit repository writes a `shallow` file
/// whose one entry is the root commit, which has no parents and hides nothing,
/// so that scan stays a genuine success.
///
/// The count is a LOWER BOUND (one absent parent hides a whole ancestry); the
/// warning says so instead of implying it measures the missing history.
///
/// A non-shallow repository pays one `shallow` file stat and nothing else.
pub(crate) fn record_shallow_history_gap(repo: &gix::Repository, source_label: &str) {
    if !repo.is_shallow() {
        return;
    }
    let boundary = match repo.shallow_commits() {
        Ok(Some(commits)) => commits,
        // `is_shallow` saw a non-empty `shallow` file that will not parse.
        // History is truncated by an unknown amount and the boundary cannot be
        // enumerated, so report the honest floor of one unscanned object.
        Ok(None) | Err(_) => {
            // LAW10: unreadable shallow metadata emits the warning below and records an explicit unscanned-object coverage gap.
            warn_shallow_history(source_label, 1);
            record_git_object_unreadable();
            return;
        }
    };
    let mut absent_parents: std::collections::HashSet<gix::ObjectId> =
        std::collections::HashSet::new();
    for boundary_id in boundary.iter() {
        let Ok(commit) = repo.find_commit(*boundary_id) else {
            // The boundary commit itself is unreadable: that alone is a
            // referenced-but-unscanned object.
            absent_parents.insert(*boundary_id);
            continue;
        };
        for parent in commit.parent_ids() {
            let parent = parent.detach();
            if !repo.has_object(parent) {
                absent_parents.insert(parent);
            }
        }
    }
    if absent_parents.is_empty() {
        return;
    }
    warn_shallow_history(source_label, absent_parents.len());
    for _ in 0..absent_parents.len() {
        record_git_object_unreadable();
    }
}

fn warn_shallow_history(source_label: &str, absent_parents: usize) {
    eprintln!(
        "keyhog: WARNING: {source_label} was pointed at a SHALLOW repository. \
         {absent_parents} parent commit(s) named at the graft boundary are not in this clone, \
         so an unknown amount of history, and every blob only those commits contain, was NOT \
         scanned. A credential that was committed and later removed will NOT be found here. \
         Fix: `git fetch --unshallow` (or `actions/checkout` with `fetch-depth: 0`), then rescan."
    );
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
        detail: format!(
            "{source_name} was truncated; {reason}; {remaining_description} were not scanned"
        ),
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
    record_git_output_line_truncated(source_name, line_kind, cap, consumed);
    SourceError::Other(format!(
        "{source_name} output was truncated: {line_kind} exceeded the {cap}-byte line cap after {consumed} bytes; the full line was not scanned"
    ))
}

/// Count + warn for an oversized git plumbing line without aborting the stream
/// (KH-1355). Callers that can skip a single line and continue use this.
pub(crate) fn record_git_output_line_truncated(
    source_name: &str,
    line_kind: &str,
    cap: usize,
    consumed: usize,
) {
    tracing::warn!(
        %source_name,
        %line_kind,
        cap,
        consumed,
        "git output line exceeded the configured byte cap; full line was NOT scanned; stream continues"
    );
    let _event = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
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

/// One capped record read: how much came off the stream, and how much of that
/// is the record itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CappedRecord {
    /// Bytes taken from the reader, including the terminating delimiter when
    /// one was present. `0` means EOF, mirroring `BufRead::read_until` so call
    /// sites branch the same.
    pub(crate) consumed: usize,
    /// Record bytes excluding the terminating delimiter. The cap applies to
    /// THIS, so a record whose content is exactly `max` bytes fits, matching
    /// every other KeyHog byte cap (1024 bytes of stdin fit
    /// `--limit-stdin-bytes 1024B`). Charging the delimiter against the cap
    /// rejected an exactly-at-cap line one byte early, and made the verdict on
    /// identical content depend on whether it was the last line of the stream.
    pub(crate) content: usize,
}

/// Read one line (through the trailing `\n`) into `buf`, capping buffered bytes
/// at `max`. If the line exceeds `max`, the first `max` bytes are kept (still
/// scanned) and the overflow is consumed and discarded so the stream stays
/// newline-aligned.
pub(crate) fn read_capped_line<R: std::io::BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<CappedRecord> {
    read_capped_record(reader, buf, max, b'\n')
}

/// Read through one delimiter while retaining at most `max` bytes. The full
/// record is always consumed so a caller can report the oversized record and
/// continue from the next exact boundary without allocating attacker-sized
/// Git output.
///
/// Retention still stops at `max` bytes, so an exactly-at-cap record keeps all
/// `max` content bytes and drops only its delimiter; callers already strip or
/// trim that delimiter (`strip_record_delimiter`, `trim_diff_line_bytes`).
pub(crate) fn read_capped_record<R: std::io::BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
    delimiter: u8,
) -> std::io::Result<CappedRecord> {
    buf.clear();
    let mut consumed = 0usize;
    loop {
        let available = match reader.fill_buf() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            // EOF without a delimiter: every consumed byte is record content.
            return Ok(CappedRecord {
                consumed,
                content: consumed,
            });
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
            return Ok(CappedRecord {
                consumed,
                content: consumed - 1,
            });
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

    /// Prune hook: true when this subtree (by object id) was already walked
    /// cleanly earlier in the same scan, so every blob identity under it is
    /// already collected. Default never prunes.
    fn subtree_already_collected(&mut self, _oid: &gix::ObjectId) -> bool {
        false
    }

    /// Called after a subtree walk completes without any new visitor error,
    /// so the collector can memoize the subtree object id.
    fn note_subtree_collected(&mut self, _oid: gix::ObjectId) {}

    /// Monotonic count of entries the visitor recorded through its
    /// `handle_*` error funnel; used to memoize only error-free subtrees.
    fn walk_error_count(&self) -> usize {
        0
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
            // Identical subtrees recur across commits/refs; a subtree already
            // walked cleanly this scan contributes the same (oid, path) blob
            // identities, which the collector dedups anyway, so skip the
            // re-descent (and its object reads) entirely.
            if visitor.subtree_already_collected(&oid) {
                continue;
            }
            let err_before = visitor.walk_error_count();
            let obj = match repo.find_object(oid) {
                Ok(obj) => obj,
                Err(error) => {
                    visitor.handle_subtree_object_error(&filepath, error.to_string())?;
                    continue;
                }
            };
            match obj.try_into_tree() {
                Ok(subtree) => {
                    walk_tree_recursive(repo, &subtree, &filepath, visitor)?;
                    if visitor.walk_error_count() == err_before {
                        visitor.note_subtree_collected(oid);
                    }
                }
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

        let record = read_capped_line(&mut r, &mut buf, 10).unwrap();
        assert_eq!(record.consumed, 101, "consumed all 100 bytes + the newline");
        assert_eq!(record.content, 100, "the newline is not record content");
        assert_eq!(
            buf.len(),
            10,
            "buffered bytes capped at max despite a 100-byte line"
        );
        assert!(buf.iter().all(|&b| b == b'x'));

        let next = read_capped_line(&mut r, &mut buf, 10).unwrap();
        assert_eq!(next.consumed, 5);
        assert_eq!(next.content, 4);
        assert_eq!(
            &buf[..],
            b"next\n",
            "stream stayed aligned; next line intact"
        );

        assert_eq!(
            read_capped_line(&mut r, &mut buf, 10).unwrap().consumed,
            0,
            "EOF"
        );
    }

    #[test]
    fn yields_final_line_without_trailing_newline() {
        let mut r = Cursor::new(b"abc".to_vec());
        let mut buf = Vec::new();
        let record = read_capped_line(&mut r, &mut buf, 100).unwrap();
        assert_eq!(record.consumed, 3);
        assert_eq!(
            record.content, 3,
            "no delimiter to discount at end of stream"
        );
        assert_eq!(&buf[..], b"abc");
        assert_eq!(read_capped_line(&mut r, &mut buf, 100).unwrap().consumed, 0);
    }

    #[test]
    fn a_line_whose_content_is_exactly_the_cap_is_not_over_cap() {
        // The cap counts record content, not the delimiter. Charging the
        // newline rejected an exactly-at-cap line one byte early, and made the
        // same content pass or fail depending only on whether a delimiter
        // followed it. Every other KeyHog byte cap admits exactly-at-cap input.
        let mut data = vec![b'x'; 10];
        data.push(b'\n');
        let mut with_newline = Cursor::new(data);
        let mut buf = Vec::new();
        let terminated = read_capped_line(&mut with_newline, &mut buf, 10).unwrap();
        assert_eq!(terminated.consumed, 11);
        assert_eq!(terminated.content, 10);
        assert!(
            terminated.content <= 10,
            "10 content bytes fit a 10-byte cap"
        );
        assert_eq!(buf.len(), 10, "all 10 content bytes are retained");

        // Identical content with no trailing delimiter must reach the same verdict.
        let mut bare = Cursor::new(vec![b'x'; 10]);
        let unterminated = read_capped_line(&mut bare, &mut buf, 10).unwrap();
        assert_eq!(unterminated.content, terminated.content);

        // One content byte past the cap is still over.
        let mut over_data = vec![b'x'; 11];
        over_data.push(b'\n');
        let mut over = Cursor::new(over_data);
        let record = read_capped_line(&mut over, &mut buf, 10).unwrap();
        assert_eq!(record.content, 11);
        assert!(record.content > 10, "11 content bytes exceed a 10-byte cap");
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

// ── Staged manifest acquisition ──────────────────────────────────────────

/// Acquire the exact ordered staged manifest from a repository.
///
/// Runs `git diff --cached --raw -z --no-renames --no-abbrev` to get the
/// exact staged object IDs and paths, classifies each entry, and computes
/// an index fingerprint for race detection.
pub(crate) fn staged_manifest_acquire(
    repo_path: &Path,
) -> Result<manifest::StagedManifest, SourceError> {
    use keyhog_core::guard_state::GitHashAlgorithm;

    let repo_root = canonical_repo_root(repo_path)?;
    let repo_arg = validate_repo_path(&repo_root)?;
    let repo = gix::open(&repo_root).map_err(|error| {
        SourceError::Git(format!(
            "failed to open repository for staged manifest: {error}"
        ))
    })?;

    // gix::hash::Kind is non_exhaustive; Sha1 is the only variant compiled
    // in (gix uses default-features = false + max-performance-safe). The
    // wildcard arm maps any future variant to Sha1 as the safe default;
    // when sha256 support is added, add an explicit arm before it.
    let hash_algorithm = match repo.object_hash() {
        gix::hash::Kind::Sha1 => GitHashAlgorithm::Sha1,
        _ => GitHashAlgorithm::Sha1,
    };

    let mut command = git_command()?;
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
        "--diff-filter=ACMRTD",
        "--end-of-options",
    ]);
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = spawn_git_child(command)?;
    let stdout = child
        .take_stdout()
        .ok_or_else(|| SourceError::Io(std::io::Error::other("missing git diff stdout")))?;

    let mut reader = std::io::BufReader::new(stdout);
    let mut header = Vec::new();
    let mut raw_path = Vec::new();
    let mut entries = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut coverage_gaps: Vec<String> = Vec::new();

    loop {
        let header_bytes =
            match read_capped_record(&mut reader, &mut header, GIT_PLUMBING_LINE_BYTES, 0) {
                Ok(record) if record.consumed == 0 => break,
                Ok(record) => record.content,
                Err(error) => {
                    return Err(SourceError::Io(error));
                }
            };
        if header_bytes > GIT_PLUMBING_LINE_BYTES {
            return Err(SourceError::Git(format!(
                "git raw staged diff header exceeded the {GIT_PLUMBING_LINE_BYTES}-byte limit"
            )));
        }
        // Strip the NUL delimiter.
        if header.last() == Some(&0) {
            header.pop();
        }

        // Parse the raw diff header: ":<mode> <old_oid> <new_oid> <status>\0<path>"
        // Format: ":100644 100644 <sha> <sha> M\0path\0"
        let header_str = std::str::from_utf8(&header).map_err(|error| {
            SourceError::Git(format!(
                "git raw staged diff header is not valid UTF-8: {error}"
            ))
        })?;

        let _path_bytes = match read_capped_record(&mut reader, &mut raw_path, 1024 * 1024, 0) {
            Ok(record) if record.consumed == 0 => {
                return Err(SourceError::Git(
                    "git raw staged diff ended before the path for an index entry".into(),
                ));
            }
            Ok(record) => record.content,
            Err(error) => return Err(SourceError::Io(error)),
        };
        if raw_path.last() == Some(&0) {
            raw_path.pop();
        }
        if raw_path.is_empty() {
            return Err(SourceError::Git(
                "git raw staged diff emitted an empty path".into(),
            ));
        }

        let mut entry = parse_raw_diff_header(header_str, &raw_path)?;
        // Look up the object size for non-deletion entries that have a blob OID.
        // Use find_header to avoid loading the full object payload into memory.
        if entry.kind != manifest::StagedEntryKind::Deletion && !entry.object_oid.is_empty() {
            if let Ok(oid) = gix::ObjectId::from_hex(entry.object_oid.as_bytes()) {
                match repo.find_header(oid) {
                    Ok(header) => entry.object_size = header.size(),
                    Err(_) => {
                        coverage_gaps.push(format!(
                            "staged object {} could not be read for size lookup",
                            entry.object_oid
                        ));
                    }
                }
            } else {
                coverage_gaps.push(format!(
                    "staged object OID '{}' is not a valid hash",
                    entry.object_oid
                ));
            }
        }
        if entry.kind != manifest::StagedEntryKind::Deletion {
            total_bytes = total_bytes.saturating_add(entry.object_size);
        }
        entries.push(entry);
    }

    if let Err(error) = wait_for_git_child(
        &mut child,
        "git diff --cached --raw",
        "reading staged manifest",
    ) {
        return Err(error);
    }

    let total_objects = entries
        .iter()
        .filter(|entry| entry.kind != manifest::StagedEntryKind::Deletion)
        .count() as u64;
    let mut manifest = manifest::StagedManifest {
        hash_algorithm,
        index_fingerprint: String::new(),
        entries,
        total_bytes,
        total_objects,
        coverage_gaps,
    };
    manifest.index_fingerprint = manifest.recompute_fingerprint();
    Ok(manifest)
}

/// Parse a raw diff header line into a manifest entry.
///
/// Format: `:<old_mode> <new_mode> <old_oid> <new_oid> <status>`
fn parse_raw_diff_header(
    header: &str,
    path_bytes: &[u8],
) -> Result<manifest::StagedManifestEntry, SourceError> {
    use manifest::{StagedEntryKind, StagedManifestEntry};

    // Header starts with ':' and has space-separated fields.
    let header = header.strip_prefix(':').ok_or_else(|| {
        SourceError::Git(format!(
            "git raw staged diff header does not start with ':': {header:?}"
        ))
    })?;

    let parts: Vec<&str> = header.splitn(5, ' ').collect();
    if parts.len() < 5 {
        return Err(SourceError::Git(format!(
            "git raw staged diff header has too few fields: {header:?}"
        )));
    }

    let new_mode = u32::from_str_radix(parts[1], 8).map_err(|error| {
        SourceError::Git(format!(
            "git raw staged diff header has invalid mode '{}': {error}",
            parts[1]
        ))
    })?;

    let new_oid = parts[3];
    let status = parts[4].chars().next().ok_or_else(|| {
        SourceError::Git(format!(
            "git raw staged diff header has empty status: {header:?}"
        ))
    })?;

    let (kind, object_oid, object_size) = match status {
        'D' => (StagedEntryKind::Deletion, String::new(), 0u64),
        'A' | 'C' | 'M' | 'T' => {
            // Added, copied, modified, type-changed: scan the new blob.
            let kind = classify_mode(new_mode);
            (kind, new_oid.to_string(), 0u64) // Size filled by caller if needed
        }
        'R' => {
            // Rename (disabled with --no-renames, but handle defensively).
            let kind = classify_mode(new_mode);
            (kind, new_oid.to_string(), 0u64)
        }
        _ => {
            return Err(SourceError::Git(format!(
                "git raw staged diff header has unknown status '{status}': {header:?}"
            )));
        }
    };

    Ok(StagedManifestEntry {
        path_bytes: path_bytes.to_vec(),
        kind,
        object_oid,
        object_size,
        raw_mode: new_mode,
    })
}

/// Classify a Git file mode into an entry kind.
fn classify_mode(mode: u32) -> manifest::StagedEntryKind {
    use manifest::StagedEntryKind;
    match mode {
        0o120000 => StagedEntryKind::Symlink,
        0o160000 => StagedEntryKind::Submodule,
        _ => StagedEntryKind::File,
    }
}
