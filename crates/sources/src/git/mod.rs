//! Shared git utilities.

use keyhog_core::SourceError;
use std::path::{Path, PathBuf};
use std::process::Command;

mod diff;
mod history;
mod source;

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

pub use diff::GitDiffSource;
pub use history::GitHistorySource;
pub use source::GitSource;

pub(crate) fn git_blob_bytes_limit_usize(limits: crate::SourceLimits) -> usize {
    match usize::try_from(limits.git_blob_bytes) {
        Ok(value) => value,
        Err(_) => usize::MAX, // LAW10: recall-safe size knob; configured cap exceeds platform usize, so saturate to the maximum representable in-memory buffer cap.
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
        let nl = available.iter().position(|&b| b == b'\n');
        let take = nl.map_or(available.len(), |i| i + 1);
        if buf.len() < max {
            let keep = take.min(max - buf.len());
            buf.extend_from_slice(&available[..keep]);
        }
        reader.consume(take);
        consumed += take;
        if nl.is_some() {
            return Ok(consumed);
        }
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

/// Parse the new-file start line from a unified-diff hunk header
/// `@@ -old_start[,old_count] +new_start[,new_count] @@ [section]`.
///
/// Returns `new_start` (1-based). The first `+` in the header is always the
/// new-side marker, so splitting on `+` and reading the leading digits is
/// robust even when the trailing section text contains a `+`. Shared by the
/// diff and history sources: both run `git diff/log -U0`, where a hunk's added
/// lines are the contiguous new-file run `new_start, new_start+1, …`, so a
/// chunk built from those lines reports absolute file lines once it carries
/// `base_line = new_start - 1`.
pub(crate) fn parse_hunk_new_start(header: &str) -> Option<usize> {
    let after_plus = header.split('+').nth(1)?;
    let digits: String = after_plus
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok() // LAW10: malformed input => None (fail-closed at the boundary), recall-safe
}

pub(crate) fn parse_hunk_new_start_or_error(
    header: &str,
    source_type: &str,
) -> Result<usize, SourceError> {
    parse_hunk_new_start(header).ok_or_else(|| {
        SourceError::Other(format!(
            "{source_type} output contains malformed unified-diff hunk header {header:?}; \
             refusing to guess line 1 because that would corrupt finding line attribution"
        ))
    })
}

#[cfg(test)]
mod hunk_header_tests {
    use super::{parse_hunk_new_start, parse_hunk_new_start_or_error};

    #[test]
    fn parses_new_start_with_and_without_count() {
        assert_eq!(parse_hunk_new_start("@@ -1,0 +90 @@"), Some(90));
        assert_eq!(parse_hunk_new_start("@@ -10,2 +12,3 @@ fn foo()"), Some(12));
        assert_eq!(parse_hunk_new_start("@@ -0,0 +1,5 @@"), Some(1));
        assert_eq!(parse_hunk_new_start("@@ -3,1 +3,1 @@ a + b"), Some(3));
        assert_eq!(parse_hunk_new_start("@@ garbage @@"), None);
    }

    #[test]
    fn malformed_hunk_header_is_error_not_line_one() {
        let err = parse_hunk_new_start_or_error("@@ garbage @@", "git diff")
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
    // Law 10: security-safe — `raw` is used ONLY for the `-`/control-char
    // pre-check and error display. A non-UTF-8 path defaulting to "." here cannot
    // bypass the real gate: line below canonicalizes the ORIGINAL `repo_path`
    // (not `raw`) and refuses anything not pointing at a real `.git`.
    let raw = repo_path.to_str().unwrap_or("."); // LAW10: absent name/label => display default; reporting-only, recall-safe
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

pub(crate) fn verify_ref(repo_path: &str, ref_name: &str) -> Result<(), SourceError> {
    let output = Command::new(&git_bin()?)
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

    Ok(())
}

pub(crate) fn get_commit_hash(repo_path: &str, ref_name: &str) -> Result<String, SourceError> {
    let output = Command::new(&git_bin()?)
        .args(["-C", repo_path, "rev-parse", "--verify", "--end-of-options"])
        .arg(format!("{ref_name}^{{commit}}"))
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        return Err(SourceError::Git(format!(
            "failed to resolve ref: {}",
            ref_name
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(crate) fn get_commit_author(repo_path: &str, ref_name: &str) -> Result<String, SourceError> {
    let output = Command::new(&git_bin()?)
        .args([
            "-C",
            repo_path,
            "log",
            "-1",
            "--format=%an",
            "--end-of-options",
        ])
        .arg(ref_name)
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SourceError::Git(format!(
            "failed to read commit author for '{}': {}",
            ref_name,
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(crate) fn get_commit_date(repo_path: &str, ref_name: &str) -> Result<String, SourceError> {
    let output = Command::new(&git_bin()?)
        .args([
            "-C",
            repo_path,
            "log",
            "-1",
            "--format=%aI",
            "--end-of-options",
        ])
        .arg(ref_name)
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SourceError::Git(format!(
            "failed to read commit date for '{}': {}",
            ref_name,
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
