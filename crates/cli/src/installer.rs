//! Shared self-install / self-update primitives.
//!
//! The in-crate seed of the planned standalone installer library: `keyhog
//! doctor`, `update`, and `repair` all build on these. Keeping them in one
//! place is what lets the premium installer commands stay thin and lets the
//! whole layer be lifted into a published crate later without re-deriving the
//! GitHub-release resolution, asset selection, version comparison, executable
//! sanity check, atomic self-replace, and end-to-end scan self-test.
//!
//! ## Responsibility split
//!
//! - [`release`] — the NETWORK + TRUST half: GitHub release resolution, asset
//!   selection, semver comparison, executable-magic sanity check, minisign
//!   signature verification, and the scan-engine self-test. It produces
//!   *verified bytes*.
//! - this module — the LOCAL-INSTALL half: resolving the running binary, the
//!   atomic / rename-away self-replace, backup + rollback, and reaping the
//!   orphaned temp artifacts a killed update leaves behind. It consumes the
//!   verified bytes and commits them to disk recoverably.
//!
//! Both halves are re-exported here so `installer::resolve_release`,
//! `installer::install_with_rollback`, etc. keep their existing paths.
//!
//! Trust model: every release binary is signed with the keyhog minisign
//! secret key in the `sign` job of `.github/workflows/release.yml`, and
//! `download_verified_asset` verifies the downloaded binary against the
//! embedded [`RELEASE_PUBLIC_KEY`] before self-replacing. A missing `.minisig`
//! fails CLOSED (refuse to install) since a forged 404 would otherwise bypass
//! the whole gate. There is no opt-out: no environment variable can disable the
//! signature gate (config-policy mandate + security).

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

mod release;
pub(crate) use release::*;

/// Resolve the running binary, following symlinks so we replace the real file.
pub(crate) fn current_binary() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe().context("locate current executable")?;
    Ok(std::fs::canonicalize(&exe).unwrap_or(exe)) // LAW10: canonicalize failure => original path (best-effort normalization); recall-safe
}

#[cfg(unix)]
pub(crate) fn install_binary(exe: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("current executable has no parent directory"))?;
    // Stage in the SAME directory so the final rename is atomic (same
    // filesystem). Unix lets you replace a running executable's file: the
    // running process keeps the old (now-unlinked) inode; the next run picks
    // up the new binary.
    let tmp = dir.join(format!(".keyhog-update-{}.tmp", std::process::id()));
    let cleanup = |e: std::io::Error| {
        let _ = std::fs::remove_file(&tmp); // LAW10: unused-binding marker; no runtime effect, not a fallback
        e
    };
    std::fs::write(&tmp, bytes)
        .map_err(cleanup)
        .with_context(|| {
            format!(
                "write new binary to {} (need write permission on the install dir; \
                 re-run with sudo or reinstall if keyhog lives in a system path)",
                dir.display()
            )
        })?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
        .map_err(cleanup)
        .context("chmod the new binary")?;
    std::fs::rename(&tmp, exe)
        .map_err(cleanup)
        .with_context(|| format!("atomically replace {}", exe.display()))?;
    Ok(())
}

/// Where the prior binary is stashed during a rename-away replace. PID-scoped
/// so concurrent updates don't collide; hidden + beside `exe` so the restore is
/// an atomic same-filesystem rename.
fn stash_path(exe: &Path) -> PathBuf {
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "keyhog".to_string()); // LAW10: absent name/label => display default; reporting-only, recall-safe
    let parent = exe.parent().unwrap_or_else(|| Path::new(".")); // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
    parent.join(format!(".{name}.keyhog-old-{}", std::process::id()))
}

/// Write `bytes` to `path` and (on unix) mark it executable.
fn write_executable(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| {
        format!(
            "write new binary to {} (the install dir must be writable; re-run with \
             elevated permissions or reinstall if keyhog lives in a system path)",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .context("chmod the new binary")?;
    }
    Ok(())
}

/// Replace `exe` with `bytes` using the rename-away dance, verifying before
/// committing and rolling back on failure. Returns the stash path of the prior
/// binary on success (the caller reaps it; on Windows the still-running image
/// stays locked until the process exits, so deletion is deferred).
///
/// Why rename-away: on Windows you cannot overwrite or delete the RUNNING
/// `.exe`, but you CAN rename it within its directory - the running process
/// keeps executing from the renamed file while the original name is freed for
/// the new binary (the same mechanism rustup and the `self-replace` crate use).
/// The dance is equally correct on Unix, so this single routine backs the
/// Windows path while being exercised by tests on the Linux host - the Windows
/// self-replace is NOT a separate, untested codepath.
pub(crate) fn replace_running_binary<F>(
    exe: &Path,
    bytes: &[u8],
    verify: F,
) -> Result<Option<PathBuf>>
where
    F: FnOnce(&Path) -> bool,
{
    replace_running_binary_checked(exe, bytes, |path| {
        if verify(path) {
            Ok(())
        } else {
            Err(anyhow!("post-install verifier returned false"))
        }
    })
}

fn replace_running_binary_checked<F>(exe: &Path, bytes: &[u8], verify: F) -> Result<Option<PathBuf>>
where
    F: FnOnce(&Path) -> Result<()>,
{
    let had_prior = exe.exists();
    let stash = stash_path(exe);

    if had_prior {
        std::fs::rename(exe, &stash).with_context(|| {
            format!(
                "stash the current binary to {} before replacing it (the install dir \
                 must be writable so a failed update can roll back)",
                stash.display()
            )
        })?;
    }

    if let Err(e) = write_executable(exe, bytes) {
        // Nothing new committed; put the original name back and bail.
        if had_prior {
            let _ = std::fs::rename(&stash, exe); // LAW10: unused-binding marker; no runtime effect, not a fallback
        }
        return Err(e);
    }

    let verify_error = match verify(exe) {
        Ok(()) => return Ok(had_prior.then_some(stash)),
        Err(error) => error,
    };

    // The new binary doesn't work on this host. It is NOT the running image
    // (the prior one, now at `stash`, is), so remove it and restore the stash.
    let _ = std::fs::remove_file(exe); // LAW10: unused-binding marker; no runtime effect, not a fallback
    if had_prior {
        std::fs::rename(&stash, exe).with_context(|| {
            format!(
                "ROLLBACK FAILED: the new binary failed its health check and the stashed \
                 working binary at {} could not be restored over {}. Restore it manually.",
                stash.display(),
                exe.display()
            )
        })?;
        return Err(anyhow!(
            "new binary failed its post-install health check: {verify_error}; rolled back to the previous \
             working binary. The release may be broken for this host (libc/GPU driver) - \
             try `keyhog update --version <older-tag>` or report the release."
        ));
    }
    Err(anyhow!(
        "installed binary failed its post-install health check: {verify_error}; removed it because no prior \
         binary to roll back to). The release may be broken for this host."
    ))
}

/// Best-effort reap of the temp artifacts a prior `update`/`repair` may have
/// left beside the binary:
///
/// * `.<name>.keyhog-old-<PID>` — the rename-away STASH from
///   `replace_running_binary` (e.g. a Windows update whose old image stayed
///   locked until its process exited).
/// * `.<name>.keyhog-bak-<PID>` — the BACKUP `install_with_rollback` copies
///   before swapping. The success/rollback paths delete it, but a process
///   KILLED (SIGKILL, power loss, OOM) between the backup copy and its removal
///   leaves it orphaned forever; without this it accumulates one stale file
///   per crashed update.
/// * `.<name>-update-<PID>.tmp` — the in-flight staging file `install_binary`
///   writes before the atomic rename; orphaned the same way on a hard kill.
///
/// Called only from `update`/`repair` (BEFORE they create their own
/// fresh-PID artifacts), never the hot scan path, so it adds no per-scan cost.
/// PID-scoped naming means it never touches the in-flight artifacts of a
/// CONCURRENT update — those carry a different PID, and a still-running peer's
/// files reappear on its own reap; the worst case is a one-cycle delay, never
/// clobbering a live update.
pub(crate) fn reap_stale_binaries(exe: &Path) {
    let Some(parent) = exe.parent() else { return };
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "keyhog".to_string()); // LAW10: absent name/label => display default; reporting-only, recall-safe
                                                  // Hidden rename-away artifacts: `.<name>.keyhog-old-*` / `.<name>.keyhog-bak-*`.
    let stash_prefix = format!(".{name}.keyhog-old-");
    let backup_prefix = format!(".{name}.keyhog-bak-");
    // In-flight staging file from the unix `install_binary`: it hardcodes
    // `.keyhog-update-<PID>.tmp` (NOT derived from the binary name), so match
    // that literal prefix — a hard SIGKILL mid-write is the only thing that
    // orphans it past `install_binary`'s own cleanup closure.
    const TMP_PREFIX: &str = ".keyhog-update-";
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(
                    dir = %parent.display(),
                    %error,
                    "cannot read installer artifact directory entry while reaping stale binaries; skipping entry"
                );
                continue;
            }
        };
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();
        let is_orphan = fname.starts_with(stash_prefix.as_str())
            || fname.starts_with(backup_prefix.as_str())
            || (fname.starts_with(TMP_PREFIX) && fname.ends_with(".tmp"));
        if is_orphan {
            let _ = std::fs::remove_file(entry.path()); // LAW10: unused-binding marker; no runtime effect, not a fallback
        }
    }
}

#[cfg(windows)]
pub(crate) fn install_binary(exe: &Path, bytes: &[u8]) -> Result<()> {
    // Rename-away replace without a health gate (that is install_with_rollback's
    // job). Leaves the prior image stashed; reaped by `reap_stale_binaries` on
    // the next update/repair once this process has exited and unlocked it.
    let _ = replace_running_binary(exe, bytes, |_| true)?; // LAW10: unused-binding marker; no runtime effect, not a fallback
    Ok(())
}

/// Path beside `exe` where the pre-overwrite binary is stashed so a broken or
/// interrupted update/repair can roll back. PID-scoped so two concurrent
/// updates don't clobber each other's backup. Same directory as `exe` so the
/// restore is an atomic same-filesystem rename.
pub(crate) fn backup_path(exe: &Path) -> PathBuf {
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "keyhog".to_string()); // LAW10: absent name/label => display default; reporting-only, recall-safe
    let parent = exe.parent().unwrap_or_else(|| Path::new(".")); // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
    parent.join(format!(".{name}.keyhog-bak-{}", std::process::id()))
}

/// Run the freshly-installed binary's own `doctor` as the post-install health
/// gate. Execs a separate process (not the in-proc self-test) so it catches a
/// binary that is signed and a valid executable but won't actually run on THIS
/// host (wrong glibc, missing shared lib). Inherits stdio so the user sees the
/// doctor report as the verification.
fn verify_via_doctor_checked(exe: &Path) -> Result<()> {
    let status = std::process::Command::new(exe)
        .arg("doctor")
        .status()
        .with_context(|| {
            format!(
                "run candidate binary health check: {} doctor",
                exe.display()
            )
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "candidate binary doctor exited with {status}; run `{}` doctor` for the full report",
            exe.display()
        ))
    }
}

/// Boolean compatibility wrapper for tests and older internal call sites.
pub(crate) fn verify_via_doctor(exe: &Path) -> bool {
    verify_via_doctor_checked(exe).is_ok()
}

fn extract_keyhog_version(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        line.trim_start()
            .strip_prefix("KeyHog v")
            .and_then(|rest| rest.split_whitespace().next())
            .filter(|version| !version.is_empty())
            .map(str::to_string)
    })
}

fn candidate_reported_version(exe: &Path) -> Result<String> {
    let output = std::process::Command::new(exe)
        .arg("--version")
        .output()
        .with_context(|| {
            format!(
                "run candidate binary version check: {} --version",
                exe.display()
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "candidate binary --version exited with {}; stderr: {}",
            output.status,
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .context("candidate binary --version wrote non-UTF-8 stdout")?;
    extract_keyhog_version(&stdout).ok_or_else(|| {
        anyhow!(
            "candidate binary --version did not print a `KeyHog v<semver>` line; stdout: {}",
            stdout.trim()
        )
    })
}

fn semver_tuple(label: &str, version: &str) -> Result<(u64, u64, u64)> {
    release::parse_semver(version)
        .ok_or_else(|| anyhow!("{label} `{version}` is not a parseable semver"))
}

/// Prove the candidate binary is both runnable and the binary that the release
/// metadata claimed. This closes the substitution-downgrade class where a
/// hostile release endpoint serves `{ tag_name: v99.0.0 }` but attaches an
/// older, correctly signed keyhog binary.
pub(crate) fn verify_candidate_release(
    exe: &Path,
    expected_release_tag: &str,
    current_version: &str,
    allow_explicit_downgrade: bool,
) -> Result<()> {
    verify_via_doctor_checked(exe)?;

    let observed_version = candidate_reported_version(exe)?;
    let observed = semver_tuple("candidate binary version", &observed_version)?;
    let expected = semver_tuple("release tag", expected_release_tag)?;
    if observed != expected {
        return Err(anyhow!(
            "candidate binary version does not match release tag: binary reports v{} but release metadata resolved {}; refusing to install a mismatched signed binary",
            observed_version,
            expected_release_tag
        ));
    }

    if !allow_explicit_downgrade {
        let current = semver_tuple("current binary version", current_version)?;
        if observed < current {
            return Err(anyhow!(
                "candidate binary reports v{} which is older than the running keyhog v{}; refusing implicit downgrade",
                observed_version,
                current_version
            ));
        }
    }

    Ok(())
}

/// Install `bytes` over `exe` and prove the result works before committing to
/// it, with automatic rollback on failure. This is the recoverability
/// invariant in code: no update/repair may leave the machine without a working
/// binary.
///
/// 1. If `exe` already exists, copy it to [`backup_path`] FIRST. If that copy
///    fails (read-only dir, no space), abort before touching `exe` - the
///    working binary stays untouched.
/// 2. Atomically replace `exe` with the new bytes (via [`install_binary`]).
/// 3. Run `verify(exe)`. On success, delete the backup and return `Ok`.
/// 4. On verify failure, restore the backup over `exe` (atomic rename) and
///    return an error. If there was no prior binary (fresh install) and verify
///    fails, remove the broken binary rather than leave it in place.
///
/// `verify` is injected so tests can drive the rollback path deterministically
/// without execing a real binary; production callers pass [`verify_via_doctor`].
#[cfg(unix)]
pub(crate) fn install_with_rollback<F>(exe: &Path, bytes: &[u8], verify: F) -> Result<()>
where
    F: FnOnce(&Path) -> bool,
{
    install_with_rollback_checked(exe, bytes, |path| {
        if verify(path) {
            Ok(())
        } else {
            Err(anyhow!("post-install verifier returned false"))
        }
    })
}

#[cfg(unix)]
pub(crate) fn install_with_rollback_checked<F>(exe: &Path, bytes: &[u8], verify: F) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    use std::os::unix::fs::PermissionsExt;
    let had_prior = exe.exists();
    let backup = backup_path(exe);

    if had_prior {
        std::fs::copy(exe, &backup).with_context(|| {
            format!(
                "back up the current binary to {} before updating (the install dir must be \
                 writable so a failed update can roll back; re-run with sudo or reinstall if \
                 keyhog lives in a system path)",
                backup.display()
            )
        })?;
        // Backup must itself be runnable for the rollback to restore a working
        // tool; mirror the 0755 we set on installs.
        std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o755)).with_context(
            || {
                format!(
                    "set executable permissions on rollback backup {} before updating",
                    backup.display()
                )
            },
        )?;
    }

    // Atomic replace. On error `exe` is untouched (write/rename either fully
    // succeed or leave the original), so just drop the backup and bail.
    if let Err(e) = install_binary(exe, bytes) {
        if had_prior {
            let _ = std::fs::remove_file(&backup); // LAW10: unused-binding marker; no runtime effect, not a fallback
        }
        return Err(e);
    }

    let verify_error = match verify(exe) {
        Ok(()) => {
            if had_prior {
                let _ = std::fs::remove_file(&backup); // LAW10: unused-binding marker; no runtime effect, not a fallback
            }
            return Ok(());
        }
        Err(error) => error,
    };

    // Verify failed: the new binary does not work on this host. Restore.
    if had_prior {
        std::fs::rename(&backup, exe).with_context(|| {
            format!(
                "ROLLBACK FAILED: the new binary failed its health check and the backup at {} \
                 could not be restored over {}. Reinstall manually from {}",
                backup.display(),
                exe.display(),
                backup.display()
            )
        })?;
        Err(anyhow!(
            "new binary failed its post-install health check: {verify_error}; rolled back to the previous \
             working binary. The release may be broken for this host (libc/GPU driver) - \
             try `keyhog update --version <older-tag>` or report the release."
        ))
    } else {
        // Fresh install with no prior binary: don't leave a broken executable.
        let _ = std::fs::remove_file(exe); // LAW10: unused-binding marker; no runtime effect, not a fallback
        Err(anyhow!(
            "installed binary failed its post-install health check: {verify_error}; removed it because no prior \
             binary to roll back to). The release may be broken for this host."
        ))
    }
}

#[cfg(windows)]
pub(crate) fn install_with_rollback<F>(exe: &Path, bytes: &[u8], verify: F) -> Result<()>
where
    F: FnOnce(&Path) -> bool,
{
    install_with_rollback_checked(exe, bytes, |path| {
        if verify(path) {
            Ok(())
        } else {
            Err(anyhow!("post-install verifier returned false"))
        }
    })
}

#[cfg(windows)]
pub(crate) fn install_with_rollback_checked<F>(exe: &Path, bytes: &[u8], verify: F) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    // Rename-away self-replace with the new binary's `doctor` as the health
    // gate and automatic rollback - the same recoverability invariant as unix,
    // via the cross-platform `replace_running_binary` (covered by tests on the
    // Linux host). The prior binary is the still-running image, locked by
    // Windows until this process exits; best-effort reap now, then leave it for
    // the next `update`/`repair` to clear via `reap_stale_binaries`.
    let stash = replace_running_binary_checked(exe, bytes, verify)?;
    if let Some(stash) = stash {
        let _ = std::fs::remove_file(&stash); // LAW10: unused-binding marker; no runtime effect, not a fallback
    }
    Ok(())
}
