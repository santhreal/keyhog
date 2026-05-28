//! Adversarial: hook install outside git repo must fail closed.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn hook_install_outside_git_repo_fails_hostile() {
    let dir = TempDir::new().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(dir.path())
        .args(["hook", "install"])
        .output()
        .expect("spawn hook install");
    assert_eq!(output.status.code(), Some(2));
    let combined = format!(
        "{}
{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.to_lowercase().contains("git") || combined.contains("hook"),
        "hook install outside repo must fail with actionable message; got: {combined}"
    );
}
