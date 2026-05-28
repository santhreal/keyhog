//! KH-GAP-081: README quickstart documents `hook install --no-daemon` but the
//! hook subcommand does not define that flag (it belongs on `scan`).

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn hook_install_rejects_no_daemon_flag_documented_in_readme() {
    let dir = TempDir::new().expect("tempdir");
    std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir.path())
        .status()
        .expect("git init");

    let output = Command::new(binary())
        .args(["hook", "install", "--no-daemon"])
        .current_dir(dir.path())
        .output()
        .expect("spawn");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "README documents hook install --no-daemon; until fixed, clap must reject it; stderr={stderr}"
    );
    assert!(
        stderr.contains("--no-daemon"),
        "expected clap rejection mentioning --no-daemon; stderr={stderr}"
    );
}
