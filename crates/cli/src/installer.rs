//! Shared self-install / self-update primitives.
//!
//! The in-crate seed of the planned standalone installer library: `keyhog
//! doctor`, `update`, and `repair` all build on these. Keeping them in one
//! place is what lets the premium installer commands stay thin and lets the
//! whole layer be lifted into a published crate later without re-deriving the
//! GitHub-release resolution, asset selection, version comparison, executable
//! sanity check, signature/checksum verification, atomic self-replace, and
//! end-to-end scan self-test.
//!
//! ## Responsibility split
//!
//! - [`release`] — the NETWORK + TRUST half: GitHub release resolution, asset
//!   selection, semver comparison, executable-magic sanity check, minisign and
//!   SHA-256 verification, and the scan-engine self-test. It produces
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
//! embedded [`RELEASE_PUBLIC_KEY`] and the release's exact SHA-256 entry before
//! self-replacing. Missing proof files fail CLOSED (refuse to install) since a
//! forged 404 would otherwise bypass the gate. There is no opt-out: no ambient
//! setting can disable release verification.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

mod release;
pub(crate) use release::*;

fn remove_installer_artifact_best_effort(path: &Path, context: &str) {
    if let Err(error) = std::fs::remove_file(path) {
        tracing::warn!(
            path = %path.display(),
            %error,
            %context,
            "failed to remove installer artifact; it may need manual cleanup"
        );
    }
}

/// Resolve the running binary, following symlinks so we replace the real file.
pub(crate) fn current_binary() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe().context("locate current executable")?;
    std::fs::canonicalize(&exe).with_context(|| {
        format!(
            "resolve current executable symlink target for {} before self-update",
            exe.display()
        )
    })
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
        remove_installer_artifact_best_effort(&tmp, "failed unix install_binary cleanup");
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
    replace_running_binary_checked(exe, bytes, bool_verify_as_result(verify))
}

fn bool_verify_as_result<F>(verify: F) -> impl FnOnce(&Path) -> Result<()>
where
    F: FnOnce(&Path) -> bool,
{
    move |path| {
        if verify(path) {
            Ok(())
        } else {
            Err(anyhow!("post-install verifier returned false"))
        }
    }
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
        // Nothing new was committed. Put the original binary back under its real
        // name and bail with the write error. If the restore ALSO fails the
        // operator's working binary is stranded at `stash` with nothing at
        // `exe` - surface that loudly (mirroring the verify-fail rollback below)
        // instead of swallowing the rename error.
        if had_prior {
            if let Err(restore_err) = std::fs::rename(&stash, exe) {
                return Err(e).with_context(|| {
                    format!(
                        "ROLLBACK FAILED after a failed binary write: the original working binary \
                         could not be restored from {} to {} ({restore_err}). It is stranded at \
                         {}; restore it manually.",
                        stash.display(),
                        exe.display(),
                        stash.display()
                    )
                });
            }
        }
        return Err(e);
    }

    let verify_error = match verify(exe) {
        Ok(()) => return Ok(had_prior.then_some(stash)),
        Err(error) => error,
    };

    // The new binary doesn't work on this host. It is NOT the running image
    // (the prior one, now at `stash`, is), so remove it and restore the stash.
    let removed = std::fs::remove_file(exe);
    if had_prior {
        // Renaming the stash back over `exe` replaces the broken binary whether
        // or not the remove above succeeded, so its result is not surfaced here.
        std::fs::rename(&stash, exe).with_context(|| {
            format!(
                "ROLLBACK FAILED: the new binary failed its health check ({verify_error}) and the \
                 stashed working binary at {} could not be restored over {}. Restore it manually.",
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
    // No prior binary to fall back to: removing the broken one is the only
    // cleanup, so report honestly whether it actually went away rather than
    // asserting "removed it" when `remove_file` may have failed.
    match removed {
        Ok(()) => Err(anyhow!(
            "installed binary failed its post-install health check: {verify_error}; removed it because no prior \
             binary to roll back to. The release may be broken for this host."
        )),
        Err(remove_err) => Err(anyhow!(
            "installed binary failed its post-install health check: {verify_error}; it could NOT be removed from \
             {} ({remove_err}) and there is no prior binary to roll back to - delete it manually. The release \
             may be broken for this host.",
            exe.display()
        )),
    }
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
/// Called only from `update`/`repair`, never the hot scan path, so it adds no
/// per-scan cost. PID-scoped naming is honored by parsing the PID suffix and
/// skipping artifacts whose owner process is still alive, so a concurrent
/// update keeps its rollback backup until it finishes.
pub(crate) fn reap_stale_binaries(exe: &Path) {
    let Some(parent) = exe.parent() else { return };
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "keyhog".to_string()); // LAW10: absent name/label => display default; reporting-only, recall-safe
                                                  // Hidden rename-away artifacts: `.<name>.keyhog-old-*` / `.<name>.keyhog-bak-*`.
    let stash_prefix = format!(".{name}.keyhog-old-");
    let backup_prefix = format!(".{name}.keyhog-bak-");
    // LAW10: stale installer artifact reap is best-effort and recall-safe;
    // read-dir failure preserves current install behavior and drops no scan coverage.
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
        if should_reap_installer_artifact(&fname, &stash_prefix, &backup_prefix) {
            remove_installer_artifact_best_effort(&entry.path(), "stale installer artifact reap");
        }
    }
}

fn should_reap_installer_artifact(fname: &str, stash_prefix: &str, backup_prefix: &str) -> bool {
    installer_artifact_pid(fname, stash_prefix, backup_prefix)
        .is_some_and(|pid| !process_is_running(pid))
}

fn installer_artifact_pid(fname: &str, stash_prefix: &str, backup_prefix: &str) -> Option<u32> {
    if let Some(raw_pid) = fname.strip_prefix(stash_prefix) {
        return parse_artifact_pid(raw_pid);
    }
    if let Some(raw_pid) = fname.strip_prefix(backup_prefix) {
        return parse_artifact_pid(raw_pid);
    }
    fname
        .strip_prefix(".keyhog-update-")
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .and_then(parse_artifact_pid)
}

fn parse_artifact_pid(raw: &str) -> Option<u32> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    match raw.parse() {
        Ok(pid) => Some(pid),
        Err(error) => {
            tracing::warn!(
                pid = raw,
                %error,
                "installer artifact filename carries an invalid PID; treating it as stale"
            );
            Some(u32::MAX)
        }
    }
}

#[cfg(unix)]
fn process_is_running(pid: u32) -> bool {
    if pid == std::process::id() {
        return false;
    }
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
fn process_is_running(pid: u32) -> bool {
    use std::ffi::c_void;

    if pid == std::process::id() {
        return false;
    }

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut c_void;
        fn CloseHandle(hObject: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        // ERROR_INVALID_PARAMETER is the normal "PID does not exist" result.
        // Access denied instead proves that a process occupies the PID but is
        // owned at a privilege boundary; deleting its rollback artifact would
        // race a live higher-privilege update.
        const ERROR_INVALID_PARAMETER: u32 = 87;
        return unsafe { GetLastError() } != ERROR_INVALID_PARAMETER;
    }
    unsafe {
        CloseHandle(handle);
    }
    true
}

#[cfg(not(any(unix, windows)))]
fn process_is_running(_pid: u32) -> bool {
    false
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
pub(crate) fn verify_via_doctor_checked(exe: &Path) -> Result<()> {
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

fn semver_version(label: &str, version: &str) -> Result<semver::Version> {
    release::parse_version(version)
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
    let observed = semver_version("candidate binary version", &observed_version)?;
    let expected = semver_version("release tag", expected_release_tag)?;
    if observed != expected {
        return Err(anyhow!(
            "candidate binary version does not match release tag: binary reports v{} but release metadata resolved {}; refusing to install a mismatched signed binary",
            observed_version,
            expected_release_tag
        ));
    }

    if !allow_explicit_downgrade {
        let current = semver_version("current binary version", current_version)?;
        if observed.cmp_precedence(&current).is_lt() {
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
/// without execing a real binary; production callers pass
/// [`verify_via_doctor_checked`].
pub(crate) fn install_with_rollback<F>(exe: &Path, bytes: &[u8], verify: F) -> Result<()>
where
    F: FnOnce(&Path) -> bool,
{
    install_with_rollback_checked(exe, bytes, bool_verify_as_result(verify))
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
            remove_installer_artifact_best_effort(
                &backup,
                "failed unix rollback backup cleanup after install error",
            );
        }
        return Err(e);
    }

    let verify_error = match verify(exe) {
        Ok(()) => {
            if had_prior {
                remove_installer_artifact_best_effort(
                    &backup,
                    "failed unix rollback backup cleanup after successful install",
                );
            }
            return Ok(());
        }
        Err(error) => error,
    };

    // Verify failed: the new binary does not work on this host. Restore.
    if had_prior {
        std::fs::rename(&backup, exe).with_context(|| {
            format!(
                "ROLLBACK FAILED: the new binary failed its health check ({verify_error}) and the \
                 backup at {} could not be restored over {}. Reinstall manually from {}",
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
        // Fresh install with no prior binary: removing the broken one is the
        // only cleanup, so report honestly whether it actually went away rather
        // than asserting "removed it" when `remove_file` may have failed.
        match std::fs::remove_file(exe) {
            Ok(()) => Err(anyhow!(
                "installed binary failed its post-install health check: {verify_error}; removed it because no prior \
                 binary to roll back to. The release may be broken for this host."
            )),
            Err(remove_err) => Err(anyhow!(
                "installed binary failed its post-install health check: {verify_error}; it could NOT be removed \
                 from {} ({remove_err}) and there is no prior binary to roll back to - delete it manually. The \
                 release may be broken for this host.",
                exe.display()
            )),
        }
    }
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
        remove_installer_artifact_best_effort(
            &stash,
            "failed windows rename-away stash cleanup after successful install",
        );
    }
    Ok(())
}
