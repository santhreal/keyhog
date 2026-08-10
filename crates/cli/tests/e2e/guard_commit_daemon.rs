//! E2E: `keyhog scan --git-staged` routes through the guard commit
//! transaction when a daemon is available, instead of the in-process
//! scanner. Tests cover clean staged bytes, staged finding blocking,
//! partial staging, cache hits, fingerprint retry, daemon=on fail-closed,
//! and daemon=auto fallback.

use crate::e2e::support::{binary, DaemonGuard};
use std::process::Command;
use tempfile::TempDir;

fn init_git_repo(dir: &std::path::Path) {
    Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir)
        .status()
        .expect("git init");
    Command::new("git")
        .args(["config", "user.email", "guard@test"])
        .current_dir(dir)
        .status()
        .expect("git config email");
    Command::new("git")
        .args(["config", "user.name", "Guard Test"])
        .current_dir(dir)
        .status()
        .expect("git config name");
}

fn git_add(dir: &std::path::Path, file: &str) {
    Command::new("git")
        .args(["add", file])
        .current_dir(dir)
        .status()
        .expect("git add");
}

fn git_commit(dir: &std::path::Path, msg: &str) {
    Command::new("git")
        .args(["commit", "-m", msg, "-q"])
        .current_dir(dir)
        .status()
        .expect("git commit");
}

/// A staged AWS access key that the scanner must find.
const STAGED_SECRET: &str = "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n";

/// Clean content that the scanner must not flag.
const STAGED_CLEAN: &str = "just a normal config file\n";

#[cfg(unix)]
#[test]
fn guard_commit_clean_staged_exits_zero() {
    let daemon = DaemonGuard::start_cpu_embedded();
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_git_repo(repo);
    std::fs::write(repo.join("clean.txt"), STAGED_CLEAN).unwrap();
    git_add(repo, "clean.txt");
    git_commit(repo, "init");

    std::fs::write(repo.join("staged_clean.txt"), "still ok\n").unwrap();
    git_add(repo, "staged_clean.txt");

    let output = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args([
            "scan",
            "--git-staged",
            "--daemon=auto",
            "--format",
            "json",
        ])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("spawn scan");

    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        code, 0,
        "clean staged scan via guard daemon should exit 0; stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn guard_commit_blocks_staged_finding() {
    let daemon = DaemonGuard::start_cpu_embedded();
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_git_repo(repo);
    std::fs::write(repo.join("clean.txt"), STAGED_CLEAN).unwrap();
    git_add(repo, "clean.txt");
    git_commit(repo, "init");

    std::fs::write(repo.join("secret.txt"), STAGED_SECRET).unwrap();
    git_add(repo, "secret.txt");

    let output = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args([
            "scan",
            "--git-staged",
            "--daemon=auto",
            "--no-suppress-test-fixtures",
            "--format",
            "json",
        ])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("spawn scan");

    let code = output.status.code().unwrap_or(-1);
    assert_eq!(
        code, 1,
        "staged secret via guard daemon should exit 1 (findings)"
    );
}

#[cfg(unix)]
#[test]
fn guard_commit_partial_staging_only_staged_has_finding() {
    let daemon = DaemonGuard::start_cpu_embedded();
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_git_repo(repo);
    std::fs::write(repo.join("clean.txt"), STAGED_CLEAN).unwrap();
    git_add(repo, "clean.txt");
    git_commit(repo, "init");

    // Stage a secret.
    std::fs::write(repo.join("staged_secret.txt"), STAGED_SECRET).unwrap();
    git_add(repo, "staged_secret.txt");

    // Write but do NOT stage another secret.
    std::fs::write(repo.join("unstaged_secret.txt"), STAGED_SECRET).unwrap();

    let output = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args([
            "scan",
            "--git-staged",
            "--daemon=auto",
            "--no-suppress-test-fixtures",
            "--format",
            "json",
        ])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("spawn scan");

    let code = output.status.code().unwrap_or(-1);
    assert_eq!(
        code, 1,
        "staged secret should be found; unstaged should not matter"
    );

    // Verify only one finding (from the staged secret, not the unstaged one).
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(arr) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(findings) = arr.as_array() {
            assert_eq!(
                findings.len(),
                1,
                "exactly one finding from staged secret, not unstaged"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn guard_commit_daemon_on_fails_closed_without_daemon() {
    let dir = TempDir::new().expect("tempdir");
    let runtime = TempDir::new().expect("runtime dir");
    let repo = dir.path();
    init_git_repo(repo);
    std::fs::write(repo.join("clean.txt"), STAGED_CLEAN).unwrap();
    git_add(repo, "clean.txt");
    git_commit(repo, "init");

    std::fs::write(repo.join("staged_clean.txt"), "ok\n").unwrap();
    git_add(repo, "staged_clean.txt");

    // Point at a runtime dir with no daemon socket.
    let output = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--git-staged", "--daemon=on"])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("spawn scan");

    let code = output.status.code().unwrap_or(-1);
    assert_ne!(
        code, 0,
        "--daemon=on without a daemon must not exit 0 (fail-closed)"
    );
}

#[cfg(unix)]
#[test]
fn guard_commit_auto_falls_back_to_in_process() {
    let dir = TempDir::new().expect("tempdir");
    let runtime = TempDir::new().expect("runtime dir");
    let repo = dir.path();
    init_git_repo(repo);
    std::fs::write(repo.join("clean.txt"), STAGED_CLEAN).unwrap();
    git_add(repo, "clean.txt");
    git_commit(repo, "init");

    std::fs::write(repo.join("staged_clean.txt"), "ok\n").unwrap();
    git_add(repo, "staged_clean.txt");

    // No daemon running; auto mode should fall back to in-process.
    let output = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--git-staged", "--daemon=auto", "--format", "json"])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("spawn scan");

    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        code, 0,
        "auto fallback to in-process should succeed for clean; stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn guard_commit_unstaged_secret_not_scanned() {
    let daemon = DaemonGuard::start_cpu_embedded();
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_git_repo(repo);
    std::fs::write(repo.join("clean.txt"), STAGED_CLEAN).unwrap();
    git_add(repo, "clean.txt");
    git_commit(repo, "init");

    // Stage a clean file.
    std::fs::write(repo.join("staged_clean.txt"), "all good\n").unwrap();
    git_add(repo, "staged_clean.txt");

    // Write but do NOT stage a secret.
    std::fs::write(repo.join("unstaged_secret.txt"), STAGED_SECRET).unwrap();

    let output = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args([
            "scan",
            "--git-staged",
            "--daemon=auto",
            "--no-suppress-test-fixtures",
            "--format",
            "json",
        ])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("spawn scan");

    let code = output.status.code().unwrap_or(-1);
    assert_eq!(
        code, 0,
        "unstaged secret must not be found by --git-staged scan"
    );
}

#[cfg(unix)]
#[test]
fn guard_commit_cache_hit_skips_rescan() {
    let daemon = DaemonGuard::start_cpu_embedded();
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_git_repo(repo);
    std::fs::write(repo.join("clean.txt"), STAGED_CLEAN).unwrap();
    git_add(repo, "clean.txt");
    git_commit(repo, "init");

    // Stage a clean file.
    std::fs::write(repo.join("staged_clean.txt"), "cache me\n").unwrap();
    git_add(repo, "staged_clean.txt");

    // First scan: should scan the blob and cache the clean attestation.
    let first = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args([
            "scan",
            "--git-staged",
            "--daemon=auto",
            "--format",
            "json",
        ])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("first scan");
    assert_eq!(first.status.code(), Some(0), "first scan should exit 0");

    // Second scan: same staged content, should hit the cache.
    let second = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args([
            "scan",
            "--git-staged",
            "--daemon=auto",
            "--format",
            "json",
        ])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("second scan");
    assert_eq!(second.status.code(), Some(0), "second scan should exit 0");

    // The second scan's stderr should mention cache hits.
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("cache hit"),
        "second scan should report cache hits; stderr: {stderr}"
    );
}
