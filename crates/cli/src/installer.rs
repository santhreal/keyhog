//! Local install primitives for `keyhog install`, `keyhog doctor`, and
//! `keyhog uninstall`.
//!
//! There is no self-update path. KeyHog ships through crates.io, and the
//! signed binary-asset release channel it used to update from is retired: no
//! workflow builds, signs, or uploads release binaries. `keyhog update` and
//! `keyhog repair` were REMOVED rather than left pointing at that channel,
//! because both searched backward for a release that still carried a complete
//! bundle, so a dead channel silently installed a long-stale binary instead of
//! failing. The download, signature-verification, asset-selection,
//! self-replace, backup/rollback, and orphan-reaping code went with them; none
//! of it had a caller once the two subcommands were gone.
//!
//! `scripts/gates/release_channel_coherence.py` keeps it that way: it fails if
//! any install/update path consumes release assets that no workflow produces.
//!
//! What remains is local: `keyhog install` compiles, authenticates, calibrates,
//! and publishes this binary's exact execution generation from the binary
//! itself, plus resolving the running binary, testing PID liveness, and the
//! doctor scan-engine self test in [`self_test`].

use anyhow::{Context, Result};

mod execution_packs;
mod self_test;
pub(crate) use execution_packs::*;
pub(crate) use self_test::*;

/// Resolve the running binary, following symlinks so callers act on the real
/// file rather than a shim. `keyhog uninstall` uses this to find what to
/// remove.
pub(crate) fn current_binary() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe().context("locate current executable")?;
    std::fs::canonicalize(&exe).with_context(|| {
        format!(
            "resolve current executable symlink target for {}",
            exe.display()
        )
    })
}

/// Is a PID occupied by a live process? Used to decide whether a temp artifact
/// belongs to a running KeyHog or is safe to reap. Own PID reports false: the
/// caller is asking about somebody else's work.
#[cfg(unix)]
pub(crate) fn process_is_running(pid: u32) -> bool {
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
pub(crate) fn process_is_running(pid: u32) -> bool {
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
        // owned at a privilege boundary; reaping its artifact would race live
        // higher-privilege work.
        const ERROR_INVALID_PARAMETER: u32 = 87;
        return unsafe { GetLastError() } != ERROR_INVALID_PARAMETER;
    }
    unsafe {
        CloseHandle(handle);
    }
    true
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn process_is_running(_pid: u32) -> bool {
    false
}
