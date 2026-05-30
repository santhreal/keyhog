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
    keyhog_core::safe_bin::resolve_safe_bin("git").ok_or_else(|| {
        SourceError::Other(
            "git binary not found in trusted system bin dirs (refusing $PATH lookup); \
             install git or set KEYHOG_TRUSTED_BIN_DIR"
                .into(),
        )
    })
}

pub use diff::GitDiffSource;
pub use history::GitHistorySource;
pub use source::GitSource;

/// Per-line read cap for `git log`/`git diff` stdout. A commit that stored a
/// single newline-free blob (minified bundle, base64 of a binary, a DB dump on
/// one line) would otherwise let `read_until`/`.lines()` grow the line buffer
/// to the full line length - unbounded memory, a DoS at internet scale. 10 MiB
/// matches the per-chunk content cap already enforced downstream.
pub(crate) const MAX_GIT_LINE_BYTES: usize = 10 * 1024 * 1024;

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
        assert_eq!(buf.len(), 10, "buffered bytes capped at max despite a 100-byte line");
        assert!(buf.iter().all(|&b| b == b'x'));

        let n2 = read_capped_line(&mut r, &mut buf, 10).unwrap();
        assert_eq!(n2, 5);
        assert_eq!(&buf[..], b"next\n", "stream stayed aligned; next line intact");

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

pub(crate) fn validate_repo_path(repo_path: &Path) -> Result<String, SourceError> {
    // SECURITY: kimi-wave1 audit finding 3.git-source-traversal. Previously
    // this only rejected leading `-` and control chars. An attacker passing
    // `--git-blobs ../../../etc` would invoke `git -C ../../../etc log ...`,
    // reading arbitrary filesystem directories through git as if they were
    // a repo. We now canonicalize the path (resolves `..` and symlinks) and
    // require it to point at an actual `.git` directory or a worktree
    // containing one. Anything else is refused.
    let raw = repo_path.to_str().unwrap_or(".");
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
