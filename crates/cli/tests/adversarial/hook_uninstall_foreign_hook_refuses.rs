//! Adversarial: hook uninstall refuses foreign pre-commit hook.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn hook_uninstall_foreign_hook_refuses() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(repo)
        .status()
        .expect("git init");
    let hooks = repo.join(".git/hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    std::fs::write(hooks.join("pre-commit"), "#!/bin/sh\necho foreign\n").unwrap();
    let output = Command::new(binary())
        .current_dir(repo)
        .args(["hook", "uninstall"])
        .output()
        .expect("spawn hook uninstall");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not installed by KeyHog") || stderr.contains("KeyHog"),
        "foreign hook uninstall must refuse; got: {stderr}"
    );
}
