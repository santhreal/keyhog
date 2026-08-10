//! E2E: `keyhog daemon status` shows guard aggregate info when roots
//! are registered.

use crate::e2e::support::{binary, DaemonGuard};
use std::process::Command;

#[cfg(unix)]
#[test]
fn daemon_status_shows_guard_aggregate() {
    let daemon = DaemonGuard::start_cpu_embedded();
    let root = tempfile::tempdir().expect("guard root tempdir");
    let root_path = root.path().canonicalize().expect("canonicalize root");
    let root_arg = root_path.to_str().expect("root path");

    // Add a guard root.
    let add = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["guard", "add", root_arg, "--mode", "filesystem"])
        .output()
        .expect("guard add");
    let add_code = add.status.code().unwrap_or(-1);
    assert!(
        add_code == 0 || add_code == 13,
        "guard add should succeed or exit 13 (stopped)"
    );

    // Check daemon status.
    let status = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["daemon", "status"])
        .output()
        .expect("daemon status");

    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        stdout.contains("guard:"),
        "daemon status should show guard aggregate line; stdout: {stdout}"
    );
    assert!(
        stdout.contains("root(s) registered"),
        "daemon status should show registered root count; stdout: {stdout}"
    );
}
