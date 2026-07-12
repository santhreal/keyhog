//! E2E R5-T-CLI: scan lockdown git staged clean exits zero.rs.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

fn init_git_repo(dir: &std::path::Path) {
    std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir)
        .status()
        .expect("git init");
    std::process::Command::new("git")
        .args(["config", "user.email", "r5-cli@test"])
        .current_dir(dir)
        .status()
        .expect("git config email");
    std::process::Command::new("git")
        .args(["config", "user.name", "R5 CLI"])
        .current_dir(dir)
        .status()
        .expect("git config name");
}

#[test]
fn scan_lockdown_git_staged_clean_exits_zero() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    // Hermetic cache: lockdown fails closed if a disk cache exists (it could
    // expose past findings), so an inherited real `~/.cache/keyhog` - or one a
    // sibling test populated in this suite — would make this non-deterministic.
    // Point HOME / XDG_CACHE_HOME at a throwaway dir so lockdown sees no cache.
    let home = TempDir::new().expect("home tempdir");
    init_git_repo(repo);
    std::fs::write(repo.join("clean.txt"), "ok\n").unwrap();
    std::process::Command::new("git")
        .args(["add", "clean.txt"])
        .current_dir(repo)
        .status()
        .expect("git add");
    std::process::Command::new("git")
        .args(["commit", "-m", "init", "-q"])
        .current_dir(repo)
        .status()
        .expect("git commit");
    std::fs::write(repo.join("staged_clean.txt"), "still ok\n").unwrap();
    std::process::Command::new("git")
        .args(["add", "staged_clean.txt"])
        .current_dir(repo)
        .status()
        .expect("git add staged clean");
    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--lockdown",
            "--git-staged",
            "--format",
            "json",
        ])
        .current_dir(repo)
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .arg(".")
        .output()
        .expect("spawn");
    let code = output.status.code();
    if code == Some(0) {
        return;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(code, Some(2), "unexpected lockdown exit; stderr={stderr}");
    assert!(
        stderr.contains("lockdown mode requested but protections failed to apply"),
        "lockdown must fail closed with an actionable hardening error; stderr={stderr}"
    );
}
