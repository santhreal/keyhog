//! Safe absolute-path resolution for external binaries we shell out to.
//!
//! Defends against `PATH` injection (kimi-wave1 audit finding 3.PATH-x):
//! `Command::new("git")` lets the user's `PATH` decide which `git` we
//! actually invoke. An attacker who can prepend a directory to `PATH` -
//! a CI runner stage, a malicious dotfile, an override in
//! `~/.config/fish/config.fish` - substitutes their own binary. Since
//! keyhog feeds the binary credential bytes (via env vars / argv / stdin
//! during git scans), that's a credential-exfil pivot.
//!
//! This module enumerates a hardcoded allowlist of system binary directories
//! plus caller-configured trusted directories loaded from `.keyhog.toml`.
//! Anything not in those dirs is refused. The allowlist is intentionally narrow
//! - distro-shipped binaries by default. Environments with Nix/Guix or other
//! non-standard binary roots must configure explicit trusted dirs through the
//! CLI config layer; no environment variable can expand this trust boundary.

use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

#[cfg(unix)]
const SYSTEM_BIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/opt/homebrew/bin", // macOS Apple Silicon
    "/opt/homebrew/sbin",
];

#[cfg(windows)]
const SYSTEM_BIN_DIRS: &[&str] = &[
    "C:\\Windows\\System32",
    "C:\\Windows",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
    "C:\\Program Files\\Git\\cmd",
    "C:\\Program Files\\Git\\bin",
];

#[cfg(unix)]
const EXE_SUFFIXES: &[&str] = &[""];

#[cfg(windows)]
const EXE_SUFFIXES: &[&str] = &[".exe", ".com", ".bat", ".cmd"];

static EXTRA_TRUSTED_BIN_DIRS: OnceLock<RwLock<Vec<PathBuf>>> = OnceLock::new();

/// Replace the caller-configured trusted binary directories.
///
/// Only absolute paths are retained. Relative paths would make the trust
/// boundary depend on the process working directory, reopening the PATH-style
/// ambiguity this module exists to avoid.
pub fn set_extra_trusted_dirs(dirs: Vec<PathBuf>) {
    // Law 10: refuse relative paths (they would make the trust boundary depend
    // on CWD) but never DROP operator config silently — surface each rejection.
    let mut filtered = Vec::with_capacity(dirs.len());
    for dir in dirs {
        if dir.is_absolute() {
            filtered.push(dir);
        } else {
            tracing::warn!(
                dir = %dir.display(),
                "ignoring relative trusted binary directory; only absolute paths are trusted"
            );
        }
    }
    let lock = EXTRA_TRUSTED_BIN_DIRS.get_or_init(|| RwLock::new(Vec::new()));
    match lock.write() {
        Ok(mut guard) => *guard = filtered,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            *guard = filtered;
        }
    }
}

fn configured_trusted_dirs() -> Vec<PathBuf> {
    let Some(lock) = EXTRA_TRUSTED_BIN_DIRS.get() else {
        return Vec::new();
    };
    match lock.read() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

fn trusted_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = SYSTEM_BIN_DIRS.iter().map(PathBuf::from).collect();
    dirs.extend(configured_trusted_dirs());
    dirs
}

/// Resolve `name` to an absolute path inside one of the trusted system
/// binary directories. Returns `None` if not found in any trusted dir
/// (do NOT fall back to `Command::new(name)` - that's exactly the bug).
///
/// A candidate is accepted only when its lexical parent is a trusted dir AND its
/// real target (following symlinks) is a regular file owned by root or the
/// current effective uid — see [`is_safe_target`]. That ownership gate narrows
/// the symlink-swap vector AT CHECK TIME without breaking legitimate cross-dir
/// symlinks (e.g. Homebrew's `/opt/homebrew/bin/git -> ../Cellar/.../git`, which
/// is owned by the installing user). The returned path is the trusted-dir path
/// (not the resolved target), so the allowlist contract is preserved.
///
/// RESIDUAL TOCTOU: the ownership check and the eventual `Command` exec are two
/// separate resolutions of the same path. In a group/user-writable trusted dir
/// an attacker who owns the dir can pass the check with a root-owned target and
/// then swap the symlink before exec. Closing this fully requires the spawn site
/// to exec the checked fd directly (fexecve / `O_PATH|O_NOFOLLOW`) or re-stat
/// immediately before spawn; this function guarantees check-time safety only.
pub fn resolve_safe_bin(name: &str) -> Option<PathBuf> {
    if name.contains('/') || name.contains('\\') {
        // Caller already passed a path; only accept if it's absolute, its
        // parent is a trusted dir, and its real target passes the safety gate.
        let p = PathBuf::from(name);
        if p.is_absolute() && in_trusted_dir(&p) && is_safe_target(&p) {
            return Some(p);
        }
        return None;
    }

    for dir in trusted_dirs() {
        for suffix in EXE_SUFFIXES {
            let candidate = dir.join(format!("{name}{suffix}"));
            if is_safe_target(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// True when `candidate` resolves (through any symlinks) to an existing REGULAR
/// FILE whose owner is root or the current effective uid.
///
/// The ownership check is the trust boundary: a symlink planted in a
/// group/user-writable trusted dir (`/usr/local/bin`, `/opt/homebrew/bin`) by
/// another, lower-privileged user points at a file THAT user owns, so its
/// uid is neither 0 nor our euid and it is refused — while root-owned system
/// binaries and self-owned package binaries (Homebrew Cellar, `cargo install`
/// shims) pass. A dangling symlink, a directory, or a device node also fails.
#[cfg(unix)]
fn is_safe_target(candidate: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // `metadata` follows symlinks, so this reflects the real target's type and
    // owner AT CHECK TIME. The target can still be swapped between this stat and
    // the later exec; see `resolve_safe_bin`'s residual-TOCTOU note.
    let Ok(meta) = std::fs::metadata(candidate) else {
        return false; // missing file or dangling symlink
    };
    if !meta.is_file() {
        return false;
    }
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let owner = meta.uid();
    owner == 0 || owner == euid
}

#[cfg(not(unix))]
fn is_safe_target(candidate: &Path) -> bool {
    candidate.is_file()
}

fn in_trusted_dir(p: &Path) -> bool {
    let parent = match p.parent() {
        Some(p) => p,
        None => return false,
    };
    trusted_dirs().iter().any(|dir| parent == dir.as_path())
}
