//! Git subprocess lifecycle for hosted-forge clones.
//!
//! Owns spawning-adjacent concerns only: bounded wait with timeout, stdout /
//! stderr drain threads, materialization caps, child termination and reaping,
//! and the askpass credential files a clone needs. The parent module owns forge
//! listing, name/URL validation, and chunk emission; it never touches a
//! `std::process` handle directly.

use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use keyhog_core::{SourceCoverageGapKind, SourceError};

use super::sanitize::sanitize_git_error_message;

pub(super) struct HostedGitCommandOutput {
    pub(super) status: ExitStatus,
    pub(super) stderr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CloneMaterializationCap {
    Bytes { observed: usize, cap: usize },
    Entries { observed: usize, cap: usize },
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CloneMaterializationGuard<'a> {
    root: &'a Path,
    byte_cap: usize,
    entry_cap: usize,
}

impl<'a> CloneMaterializationGuard<'a> {
    /// Bind a clone destination to the byte and entry ceilings the caller
    /// resolved. The caps stay private so every guard carries limits that came
    /// from `SourceLimits` rather than an ad-hoc literal at a call site.
    pub(super) fn new(root: &'a Path, byte_cap: usize, entry_cap: usize) -> Self {
        Self {
            root,
            byte_cap,
            entry_cap,
        }
    }
}

#[derive(Debug)]
pub(super) enum HostedGitWaitError {
    Command(String),
    MaterializationCap {
        cap: CloneMaterializationCap,
        cleanup_error: Option<String>,
    },
}

pub(super) fn clone_materialization_truncated(
    platform: &str,
    repo_display_path: &str,
    cap: CloneMaterializationCap,
    cleanup_error: Option<&str>,
) -> SourceError {
    let mut detail = match cap {
        CloneMaterializationCap::Bytes { observed, cap } => format!(
            "clone materialization reached or exceeded the git_total_bytes cap ({observed} bytes observed, cap {cap}); the clone was stopped and was not scanned"
        ),
        CloneMaterializationCap::Entries { observed, cap } => format!(
            "clone materialization reached or exceeded the git_chunk_count entry cap ({observed} entries observed, cap {cap}); the clone was stopped and was not scanned"
        ),
    };
    if let Some(error) = cleanup_error {
        detail.push_str("; child cleanup also failed: ");
        detail.push_str(error);
    }
    SourceError::Coverage {
        adapter: platform.to_string(),
        surface: "clone".to_string(),
        target: repo_display_path.to_string(),
        kind: SourceCoverageGapKind::Truncated,
        detail,
    }
}

pub(super) fn clone_materialization_cap(
    guard: CloneMaterializationGuard<'_>,
) -> Result<Option<CloneMaterializationCap>, std::io::Error> {
    let root_metadata = match std::fs::symlink_metadata(guard.root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !root_metadata.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "clone target became a non-directory",
        ));
    }

    let mut bytes = 0_usize;
    let mut entries = 0_usize;
    let mut directories = vec![guard.root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        let directory_metadata = match std::fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !directory_metadata.file_type().is_dir() {
            continue;
        }
        let children = match std::fs::read_dir(&directory) {
            Ok(children) => children,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for child in children {
            let child = match child {
                Ok(child) => child,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            entries = match entries.checked_add(1) {
                Some(entries) => entries,
                None => {
                    return Ok(Some(CloneMaterializationCap::Entries {
                        observed: usize::MAX,
                        cap: guard.entry_cap,
                    }))
                }
            };
            if entries > guard.entry_cap {
                return Ok(Some(CloneMaterializationCap::Entries {
                    observed: entries,
                    cap: guard.entry_cap,
                }));
            }

            let metadata = match std::fs::symlink_metadata(child.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let size = match usize::try_from(metadata.len()) {
                Ok(size) => size,
                Err(_) => {
                    // LAW10: bounded conversion failure returns an operator-visible clone byte-cap result; no oversized materialization is treated as complete.
                    return Ok(Some(CloneMaterializationCap::Bytes {
                        observed: usize::MAX,
                        cap: guard.byte_cap,
                    }));
                }
            };
            bytes = match bytes.checked_add(size) {
                Some(bytes) => bytes,
                None => {
                    return Ok(Some(CloneMaterializationCap::Bytes {
                        observed: usize::MAX,
                        cap: guard.byte_cap,
                    }))
                }
            };
            if bytes > guard.byte_cap {
                return Ok(Some(CloneMaterializationCap::Bytes {
                    observed: bytes,
                    cap: guard.byte_cap,
                }));
            }
            if metadata.file_type().is_dir() {
                directories.push(child.path());
            }
        }
    }
    Ok(None)
}

pub(super) fn wait_for_command_with_timeout(
    mut child: Child,
    stdout_drain: Option<thread::JoinHandle<Result<(), String>>>,
    stderr_drain: Option<thread::JoinHandle<String>>,
    timeout: Duration,
    materialization_guard: CloneMaterializationGuard<'_>,
) -> Result<HostedGitCommandOutput, HostedGitWaitError> {
    let start = Instant::now();
    let mut stdout_drain = stdout_drain;
    let mut stderr_drain = stderr_drain;
    loop {
        match clone_materialization_cap(materialization_guard) {
            Ok(Some(cap)) => {
                let cleanup_error = terminate_hosted_git_child(
                    &mut child,
                    stdout_drain.take(),
                    stderr_drain.take(),
                )
                .err();
                return Err(HostedGitWaitError::MaterializationCap { cap, cleanup_error });
            }
            Ok(None) => {}
            Err(error) => {
                terminate_hosted_git_child(&mut child, stdout_drain.take(), stderr_drain.take())
                    .map_err(HostedGitWaitError::Command)?;
                return Err(HostedGitWaitError::Command(format!(
                    "git clone materialization monitor failed: {error}; child was killed and reaped"
                )));
            }
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                match clone_materialization_cap(materialization_guard) {
                    Ok(Some(cap)) => {
                        let cleanup_error = terminate_hosted_git_child(
                            &mut child,
                            stdout_drain.take(),
                            stderr_drain.take(),
                        )
                        .err();
                        return Err(HostedGitWaitError::MaterializationCap { cap, cleanup_error });
                    }
                    Ok(None) => {}
                    Err(error) => {
                        terminate_hosted_git_child(
                            &mut child,
                            stdout_drain.take(),
                            stderr_drain.take(),
                        )
                        .map_err(HostedGitWaitError::Command)?;
                        return Err(HostedGitWaitError::Command(format!(
                            "git clone materialization monitor failed after child exit: {error}"
                        )));
                    }
                }
                return finish_hosted_git_child(status, stdout_drain.take(), stderr_drain.take())
                    .map_err(HostedGitWaitError::Command);
            }
            Ok(None) => {}
            Err(error) => {
                kill_and_reap_child(&mut child).map_err(|cleanup_error| {
                    HostedGitWaitError::Command(format!(
                        "git clone status check failed: {error}; additionally failed to stop child: {cleanup_error}"
                    ))
                })?;
                let stdout_cleanup = match join_hosted_git_stdout(stdout_drain.take()) {
                    Ok(()) => String::new(),
                    Err(error) => format!("; stdout cleanup failed: {error}"),
                };
                let stderr = join_hosted_git_stderr(stderr_drain.take());
                let stderr_suffix = hosted_git_stderr_suffix(&stderr);
                return Err(HostedGitWaitError::Command(format!(
                    "git clone status check failed: {error}; child was killed and reaped{stdout_cleanup}{stderr_suffix}"
                )));
            }
        }

        if start.elapsed() >= timeout {
            kill_and_reap_child(&mut child).map_err(|cleanup_error| {
                HostedGitWaitError::Command(format!(
                    "git clone timed out after {}s; additionally failed to stop child: {cleanup_error}",
                    timeout.as_secs()
                ))
            })?;
            let stderr = join_hosted_git_stderr(stderr_drain.take());
            let stderr_suffix = hosted_git_stderr_suffix(&stderr);
            let stdout_cleanup = match join_hosted_git_stdout(stdout_drain.take()) {
                Ok(()) => String::new(),
                Err(error) => format!("; stdout cleanup failed: {error}"),
            };
            return Err(HostedGitWaitError::Command(format!(
                "git clone timed out after {}s{stdout_cleanup}{stderr_suffix}",
                timeout.as_secs()
            )));
        }

        thread::sleep(Duration::from_millis(100));
    }
}

fn terminate_hosted_git_child(
    child: &mut Child,
    stdout_drain: Option<thread::JoinHandle<Result<(), String>>>,
    stderr_drain: Option<thread::JoinHandle<String>>,
) -> Result<(), String> {
    kill_and_reap_child(child)?;
    let stdout_result = join_hosted_git_stdout(stdout_drain);
    let _stderr = join_hosted_git_stderr(stderr_drain);
    stdout_result
}

fn finish_hosted_git_child(
    status: ExitStatus,
    stdout_drain: Option<thread::JoinHandle<Result<(), String>>>,
    stderr_drain: Option<thread::JoinHandle<String>>,
) -> Result<HostedGitCommandOutput, String> {
    let stdout_result = join_hosted_git_stdout(stdout_drain);
    let stderr = join_hosted_git_stderr(stderr_drain);
    stdout_result?;
    Ok(HostedGitCommandOutput { status, stderr })
}

fn join_hosted_git_stdout(
    stdout_drain: Option<thread::JoinHandle<Result<(), String>>>,
) -> Result<(), String> {
    match stdout_drain {
        Some(handle) => match handle.join() {
            Ok(result) => result,
            Err(_panic_payload) => Err("git clone stdout reader panicked".to_string()),
        },
        None => Ok(()),
    }
}

fn join_hosted_git_stderr(stderr_drain: Option<thread::JoinHandle<String>>) -> String {
    match stderr_drain {
        Some(handle) => match handle.join() {
            Ok(stderr) => stderr,
            Err(_panic_payload) => "stderr unavailable: git clone stderr reader panicked".into(),
        },
        None => "stderr unavailable: git clone stderr was not captured".into(),
    }
}

pub(super) fn hosted_git_stderr_suffix(stderr: &str) -> String {
    let stderr = sanitize_git_error_message(stderr);
    if stderr.is_empty() {
        String::new()
    } else {
        format!("; git stderr: {stderr}")
    }
}

pub(super) fn drain_hosted_git_stdout(mut stdout_pipe: impl std::io::Read) -> Result<(), String> {
    let mut buffer = [0_u8; 8192];
    loop {
        match std::io::Read::read(&mut stdout_pipe, &mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) => return Err(format!("stdout unavailable: {error}")),
        }
    }
}

fn kill_and_reap_child(child: &mut std::process::Child) -> Result<(), String> {
    let kill_result = child.kill();
    let wait_result = child.wait();
    match (kill_result, wait_result) {
        (_, Ok(_status)) => Ok(()),
        (Ok(()), Err(wait_error)) => Err(format!("failed to reap child: {wait_error}")),
        (Err(kill_error), Err(wait_error)) => Err(format!(
            "failed to kill child: {kill_error}; failed to reap child: {wait_error}"
        )),
    }
}

#[derive(Debug)]
pub(super) struct GitAskpassAuth {
    _dir: tempfile::TempDir,
    pub(super) askpass_path: PathBuf,
}

impl GitAskpassAuth {
    pub(super) fn create(
        platform: &str,
        username: &str,
        secret: &str,
        expected_prompt_host: &str,
    ) -> Result<Self, SourceError> {
        validate_auth_part(platform, "username", username)?;
        validate_auth_part(platform, "token", secret)?;
        validate_auth_part(platform, "expected clone host", expected_prompt_host)?;

        let dir = tempfile::tempdir().map_err(SourceError::Io)?;
        let username_path = dir.path().join("username");
        let token_path = dir.path().join("token");
        let origin_path = dir.path().join("origin-host");
        write_secret_file(&username_path, username.as_bytes())?;
        write_secret_file(&token_path, secret.as_bytes())?;
        write_secret_file(&origin_path, expected_prompt_host.as_bytes())?;

        let askpass_path = if cfg!(unix) {
            let path = dir.path().join("askpass.sh");
            // Host-boundary match only. Substring *"$ORIGIN"* leaked forge
            // tokens to notgithub.com / github.com.evil / evil-github.com.
            // Require ORIGIN as a URL host (after :// or @) followed by a host
            // terminator so lookalike hosts cannot match.
            write_askpass_file(
                &path,
                b"#!/bin/sh\nset -eu\nDIR=${0%/*}\n[ \"$DIR\" != \"$0\" ] || DIR=.\nread_one() {\n  IFS= read -r line < \"$1\" || [ -n \"${line-}\" ] || exit 1\n  printf '%s\\n' \"$line\"\n}\nORIGIN=$(read_one \"$DIR/origin-host\")\ncase \"${1-}\" in\n*\"://${ORIGIN}/\"*|*\"://${ORIGIN}:\"*|*\"://${ORIGIN}'\"*|*\"://${ORIGIN}\\\"\"*|*\"://${ORIGIN}?\"*|*\"://${ORIGIN}#\"*|*\"@${ORIGIN}/\"*|*\"@${ORIGIN}:\"*|*\"@${ORIGIN}'\"*|*\"@${ORIGIN}\\\"\"*|*\"@${ORIGIN}?\"*|*\"@${ORIGIN}#\"*) ;;\n*) printf '%s\\n' \"keyhog: refusing git credential prompt outside expected origin\" >&2; exit 1 ;;\nesac\ncase \"${1-}\" in\n*Username*) read_one \"$DIR/username\" ;;\n*) read_one \"$DIR/token\" ;;\nesac\n",
            )?;
            path
        } else {
            let path = dir.path().join("askpass.bat");
            // Literal host-boundary needles (not bare !origin!) so findstr
            // cannot match lookalike hosts. Keep delayed expansion for the
            // prompt to avoid %metachar% expansion.
            let content = format!(
                concat!(
                    "@echo off\r\n",
                    "setlocal EnableExtensions EnableDelayedExpansion\r\n",
                    "set \"prompt=%~1\"\r\n",
                    "set /p origin=<\"{}\"\r\n",
                    "echo(!prompt!| findstr /I /L ",
                    "/C:\"://!origin!/\" ",
                    "/C:\"://!origin!:\" ",
                    "/C:\"://!origin!'\" ",
                    "/C:\"://!origin!\"\" ",
                    "/C:\"@!origin!/\" ",
                    "/C:\"@!origin!:\" ",
                    "/C:\"@!origin!'\" ",
                    "/C:\"@!origin!\"\" ",
                    ">nul\r\n",
                    "if errorlevel 1 (\r\n",
                    "  >&2 echo keyhog: refusing git credential prompt outside expected origin\r\n",
                    "  exit /b 1\r\n",
                    ")\r\n",
                    "echo(!prompt!| findstr /I /C:\"Username\" >nul\r\n",
                    "if not errorlevel 1 (\r\n",
                    "  type \"{}\"\r\n",
                    ") else (\r\n",
                    "  type \"{}\"\r\n",
                    ")\r\n",
                ),
                origin_path.display(),
                username_path.display(),
                token_path.display()
            );
            write_askpass_file(&path, content.as_bytes())?;
            path
        };

        Ok(Self {
            _dir: dir,
            askpass_path,
        })
    }
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), SourceError> {
    #[cfg(unix)]
    return write_private_file(path, bytes, 0o600);
    #[cfg(not(unix))]
    write_private_file(path, bytes)
}

fn write_askpass_file(path: &Path, bytes: &[u8]) -> Result<(), SourceError> {
    #[cfg(unix)]
    return write_private_file(path, bytes, 0o700);
    #[cfg(not(unix))]
    write_private_file(path, bytes)
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8], unix_mode: u32) -> Result<(), SourceError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    options.mode(unix_mode);

    let mut file = options.open(path).map_err(SourceError::Io)?;
    file.write_all(bytes).map_err(SourceError::Io)
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), SourceError> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    let mut file = options.open(path).map_err(SourceError::Io)?;
    file.write_all(bytes).map_err(SourceError::Io)
}

pub(super) fn validate_auth_part(
    platform: &str,
    label: &str,
    value: &str,
) -> Result<(), SourceError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(SourceError::Other(format!(
            "{platform}: {label} contains unsafe characters"
        )));
    }
    Ok(())
}
