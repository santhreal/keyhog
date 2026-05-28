//! R5-T adversarial non-scan: hook install outside git repo exits 2.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn r5t_hook_install_outside_repo_stderr_actionable() {
    let dir = TempDir::new().expect("tempdir");
    let output = Command::new(binary())
        .args(["hook", "install"])
        .current_dir(dir.path())
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_ascii_lowercase().contains("git") || stderr.contains("repository"),
        "hook install outside repo must mention git; got: {stderr}"
    );
}
