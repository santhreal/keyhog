//! R5-T adversarial non-scan: hook uninstall on clean repo without hook exits 0.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

fn init_git(dir: &std::path::Path) {
    std::process::Command::new("git").args(["init", "-q"]).current_dir(dir).status().unwrap();
    std::process::Command::new("git").args(["config", "user.email", "r5t@test"]).current_dir(dir).status().unwrap();
    std::process::Command::new("git").args(["config", "user.name", "R5T"]).current_dir(dir).status().unwrap();
}

#[test]
fn r5t_hook_uninstall_clean_repo_exits_zero() {
    let dir = TempDir::new().expect("tempdir");
    init_git(dir.path());
    let output = Command::new(binary())
        .args(["hook", "uninstall"])
        .current_dir(dir.path())
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
}
