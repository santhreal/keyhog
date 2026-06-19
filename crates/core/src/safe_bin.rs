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
    let filtered = dirs
        .into_iter()
        .filter(|dir| dir.is_absolute())
        .collect::<Vec<_>>();
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
/// Resolve a binary name to an absolute path, defending against PATH injection.
pub fn resolve_safe_bin(name: &str) -> Option<PathBuf> {
    if name.contains('/') || name.contains('\\') {
        // Caller already passed a path; only accept if it's absolute and
        // points inside a trusted dir.
        let p = PathBuf::from(name);
        if p.is_absolute() && in_trusted_dir(&p) && p.exists() {
            return Some(p);
        }
        return None;
    }

    for dir in trusted_dirs() {
        for suffix in EXE_SUFFIXES {
            let candidate = dir.join(format!("{name}{suffix}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Compatibility shim for old downstream callers that expected
/// `Command::new(name)` semantics when no trusted absolute binary was found.
///
/// Keyhog production code must use `resolve_safe_bin` directly and refuse on
/// `None`, even for host probes. PATH fallback lets caller-controlled process
/// state select an executable and is not an acceptable production routing path.
#[deprecated(
    note = "PATH fallback is compatibility-only; production code must call resolve_safe_bin and fail closed on None"
)]
pub fn resolve_or_fallback(name: &str) -> PathBuf {
    if let Some(p) = resolve_safe_bin(name) {
        return p;
    }
    tracing::warn!(
        "keyhog: '{name}' not found in trusted system bin dirs; falling back to PATH lookup. \
         Configure [system].trusted_bin_dirs in .keyhog.toml if running on a non-standard distro."
    );
    PathBuf::from(name)
}

fn in_trusted_dir(p: &Path) -> bool {
    let parent = match p.parent() {
        Some(p) => p,
        None => return false,
    };
    trusted_dirs().iter().any(|dir| parent == dir.as_path())
}
