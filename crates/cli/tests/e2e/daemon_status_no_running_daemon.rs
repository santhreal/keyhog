//! E2E: `daemon status` without a running daemon exits non-zero.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn daemon_status_no_running_daemon() {
    let runtime = TempDir::new().expect("runtime");
    let output = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["daemon", "status"])
        .output()
        .expect("spawn");
    assert_ne!(
        output.status.code(),
        Some(0),
        "status without daemon must not exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
