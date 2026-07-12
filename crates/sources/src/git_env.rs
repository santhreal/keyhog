//! Hermetic git spawn factory — the ONE owner of the trusted-binary resolution
//! and isolation environment every git invocation needs.
//!
//! This lives OUTSIDE the `git` module because it must be reachable from two
//! independently-gated callers: the full git source (`#[cfg(feature = "git")]`)
//! AND the hosted-git clone path (`#[cfg(any(feature = "github", "gitlab",
//! "bitbucket"))]`). Routing both through here means a hosted clone gets the same
//! `GIT_CONFIG_GLOBAL/SYSTEM` nulling as every other spawn, and the isolation
//! set cannot drift between the two entry points.

use keyhog_core::SourceError;
use std::path::PathBuf;
use std::process::Command;

/// Platform null device. A git config path pointing here reads as "no config"
/// on both Git-for-Windows (`NUL`) and POSIX git (`/dev/null`).
const GIT_NULL_CONFIG: &str = if cfg!(windows) { "NUL" } else { "/dev/null" };

/// Resolve `git` to an absolute path inside a trusted system bin dir.
/// SECURITY (kimi-wave1 audit finding 3.PATH-git): refuses to fall back to
/// `Command::new("git")`, which would let a hostile `$PATH` substitute the git
/// binary at runtime — keyhog feeds git the repo path and scans the blob bytes
/// it returns, so a substituted git could exfiltrate credentials directly.
pub(crate) fn git_bin() -> Result<PathBuf, SourceError> {
    keyhog_core::resolve_safe_bin("git").ok_or_else(|| {
        SourceError::Other(
            "git binary not found in trusted system bin dirs (refusing $PATH lookup); \
             install git or add its absolute directory to [system].trusted_bin_dirs in .keyhog.toml"
                .into(),
        )
    })
}

/// Apply the hermetic isolation env to a git [`Command`]. Nulling the global +
/// system config disables ALL host config (`commit.gpgsign`, `credential.helper`,
/// `core.hooksPath`, …) so no host setting can hook, sign, or block-on-prompt a
/// keyhog git spawn (a latent CI hang; Testing-Contract HOST-INDEPENDENCE).
/// ONE PLACE for the isolation set shared by [`git_command`] and any caller that
/// must build its own `Command` (e.g. the hosted clone, which layers askpass).
pub(crate) fn apply_hermetic_git_env(command: &mut Command) -> &mut Command {
    command
        .env("GIT_CONFIG_GLOBAL", GIT_NULL_CONFIG)
        .env("GIT_CONFIG_SYSTEM", GIT_NULL_CONFIG)
        .env("GIT_TERMINAL_PROMPT", "0")
}

/// Build a `git` [`Command`] with the resolved safe binary AND the hermetic
/// environment. ONE PLACE: every git spawn goes through here rather than
/// `Command::new(git_bin()?)`, so the isolation cannot drift per call site.
pub(crate) fn git_command() -> Result<Command, SourceError> {
    let mut command = Command::new(git_bin()?);
    apply_hermetic_git_env(&mut command);
    Ok(command)
}
