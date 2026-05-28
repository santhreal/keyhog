//! Adversarial: hook uninstall outside git repo must fail.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn hook_uninstall_outside_git_repo_fails_hostile() {
    let dir = TempDir::new().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(dir.path())
        .args(["hook", "uninstall"])
        .output()
        .expect("spawn hook uninstall");
    assert_eq!(output.status.code(), Some(2));
    let combined = format!(
        "{}
{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.to_lowercase().contains("git"),
        "hook uninstall outside repo must mention git; got: {combined}"
    );
}
