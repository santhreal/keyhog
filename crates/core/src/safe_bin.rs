//! Safe absolute-path resolution for external binaries we shell out to.
//!
//! Defends against `PATH` injection (kimi-wave1 audit finding 3.PATH-x):
//! `Command::new("git")` lets the user's `PATH` decide which `git` we
//! actually invoke. An attacker who can prepend a directory to `PATH` —
//! a CI runner stage, a malicious dotfile, an override in
//! `~/.config/fish/config.fish` — substitutes their own binary. Since
//! keyhog feeds the binary credential bytes (via env vars / argv / stdin
//! during git scans), that's a credential-exfil pivot.
//!
//! This module enumerates a hardcoded allowlist of system binary
//! directories and returns the FIRST match. Anything not in those dirs
//! is refused. The allowlist is intentionally narrow — distro-shipped
//! binaries only. If your environment legitimately needs a different
//! path, set the `KEYHOG_TRUSTED_BIN_DIR` env var (colon-separated on
//! Unix, semicolon-separated on Windows) — but be aware that anyone
//! who can set that env var can already inject anyway, so the env-var
//! path exists for ops convenience, not as a security boundary.

use std::path::PathBuf;

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

/// Resolve `name` to an absolute path inside one of the trusted system
/// binary directories. Returns `None` if not found in any trusted dir
/// (do NOT fall back to `Command::new(name)` — that's exactly the bug).
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

    let mut search_dirs: Vec<PathBuf> = SYSTEM_BIN_DIRS.iter().map(PathBuf::from).collect();
    if let Ok(extra) = std::env::var("KEYHOG_TRUSTED_BIN_DIR") {
        let sep = if cfg!(windows) { ';' } else { ':' };
        for dir in extra.split(sep).filter(|s| !s.is_empty()) {
            search_dirs.push(PathBuf::from(dir));
        }
    }

    for dir in &search_dirs {
        for suffix in EXE_SUFFIXES {
            let candidate = dir.join(format!("{name}{suffix}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Resolve `name` or fall back to `Command::new(name)` semantics if
/// nothing trusted was found. Intended for read-only / probe sites
/// (hardware detection, version queries) where blocking the command
/// would degrade UX more than the marginal risk warrants. Logs a
/// warning so the operator knows the unsafe fallback fired.
///
/// For sites that handle credential bytes (git scans, docker pulls),
/// use `resolve_safe_bin` directly and refuse on `None`.
pub fn resolve_or_fallback(name: &str) -> PathBuf {
    if let Some(p) = resolve_safe_bin(name) {
        return p;
    }
    tracing::warn!(
        "keyhog: '{name}' not found in trusted system bin dirs; falling back to PATH lookup. \
         Set KEYHOG_TRUSTED_BIN_DIR if running on a non-standard distro."
    );
    PathBuf::from(name)
}

fn in_trusted_dir(p: &std::path::Path) -> bool {
    let parent = match p.parent() {
        Some(p) => p,
        None => return false,
    };
    SYSTEM_BIN_DIRS
        .iter()
        .any(|d| parent == std::path::Path::new(d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn resolves_sh_to_known_path() {
        // `/bin/sh` exists on every Unix variant we ship to.
        let resolved = resolve_safe_bin("sh").expect("sh should resolve");
        assert!(resolved.is_absolute());
        assert!(resolved.ends_with("sh"));
    }

    #[test]
    fn refuses_relative_path() {
        assert!(resolve_safe_bin("./malicious").is_none());
        assert!(resolve_safe_bin("../../../bin/sh").is_none());
    }

    #[test]
    fn refuses_absolute_path_outside_trusted_dirs() {
        assert!(resolve_safe_bin("/tmp/whatever").is_none());
    }

    #[test]
    fn unknown_binary_is_none() {
        // A name that should never exist on any system.
        assert!(resolve_safe_bin("definitely-not-a-real-binary-xyz123").is_none());
    }
}
