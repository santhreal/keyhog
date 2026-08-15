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

/// Provider-shaped value whose tier depends on staged source-path semantics.
const STAGED_PROVIDER_TOKEN: &str = concat!(
    "ABUSEIPDB_API_KEY=",
    "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    "\n"
);

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
        .args(["scan", "--git-staged", "--daemon=auto", "--format", "json"])
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

    std::fs::write(repo.join(".env.secret"), STAGED_SECRET).unwrap();
    git_add(repo, ".env.secret");

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
fn guard_commit_preserves_path_conditioned_evidence_policy() {
    let daemon = DaemonGuard::start_cpu_embedded();
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_git_repo(repo);
    std::fs::write(repo.join("clean.txt"), STAGED_CLEAN).unwrap();
    git_add(repo, "clean.txt");
    git_commit(repo, "init");

    std::fs::write(repo.join(".env.provider"), STAGED_PROVIDER_TOKEN).unwrap();
    git_add(repo, ".env.provider");
    let credential_role = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["scan", "--git-staged", "--daemon=on", "--format", "json"])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("scan credential-bearing staged path");
    assert_eq!(
        credential_role.status.code(),
        Some(1),
        "credential-bearing staged paths must preserve likely evidence through the guard daemon; stderr={}",
        String::from_utf8_lossy(&credential_role.stderr)
    );
    let credential_report: serde_json::Value =
        serde_json::from_slice(&credential_role.stdout).expect("credential-role JSON report");
    assert_eq!(credential_report.as_array().map(Vec::len), Some(1));
    assert_eq!(credential_report[0]["evidence"]["tier"], "likely");
    assert_eq!(
        credential_report[0]["evidence"]["reason_code"],
        "vendor-pattern"
    );
    assert!(
        credential_report[0]["location"]["file_path"]
            .as_str()
            .is_some_and(|path| path.ends_with(".env.provider")),
        "guard report must retain the staged source path: {credential_report}"
    );

    std::fs::write(repo.join(".env.provider"), STAGED_CLEAN).unwrap();
    git_add(repo, ".env.provider");
    std::fs::write(repo.join("provider.txt"), STAGED_PROVIDER_TOKEN).unwrap();
    git_add(repo, "provider.txt");
    let review_default = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["scan", "--git-staged", "--daemon=on", "--format", "json"])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("scan unsupported staged path under default policy");
    assert_eq!(
        review_default.status.code(),
        Some(0),
        "review evidence must remain non-blocking under the default guard policy; stderr={}",
        String::from_utf8_lossy(&review_default.stderr)
    );
    let review_report: serde_json::Value =
        serde_json::from_slice(&review_default.stdout).expect("default review JSON report");
    assert_eq!(review_report.as_array().map(Vec::len), Some(1));
    assert_eq!(review_report[0]["evidence"]["tier"], "review");
    assert_eq!(
        review_report[0]["evidence"]["reason_code"],
        "unsupported-context"
    );

    let review_paranoid = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args([
            "scan",
            "--git-staged",
            "--daemon=on",
            "--evidence-policy",
            "paranoid",
            "--format",
            "json",
        ])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("scan unsupported staged path under paranoid policy");
    assert_eq!(
        review_paranoid.status.code(),
        Some(1),
        "review evidence must block the paranoid guard policy; stderr={}",
        String::from_utf8_lossy(&review_paranoid.stderr)
    );
    let paranoid_report: serde_json::Value =
        serde_json::from_slice(&review_paranoid.stdout).expect("paranoid review JSON report");
    assert_eq!(paranoid_report, review_report);
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
    std::fs::write(repo.join(".env.staged-secret"), STAGED_SECRET).unwrap();
    git_add(repo, ".env.staged-secret");

    // Write but do NOT stage another secret.
    std::fs::write(repo.join(".env.unstaged-secret"), STAGED_SECRET).unwrap();

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

    // No daemon is running. Pin the diagnostic CPU route so this test isolates
    // daemon fallback from the independent fail-closed autoroute contract.
    let output = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args([
            "scan",
            "--git-staged",
            "--daemon=auto",
            "--backend",
            "cpu",
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
    std::fs::write(repo.join(".env.unstaged-secret"), STAGED_SECRET).unwrap();

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
        .args(["scan", "--git-staged", "--daemon=auto", "--format", "json"])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("first scan");
    assert_eq!(first.status.code(), Some(0), "first scan should exit 0");

    // Second scan: same staged content, should hit the cache.
    let second = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["scan", "--git-staged", "--daemon=auto", "--format", "json"])
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
#[cfg(unix)]
#[test]
fn guard_commit_aliases_scan_each_path_with_one_blob_payload() {
    let daemon = DaemonGuard::start_cpu_embedded();
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_git_repo(repo);
    std::fs::write(repo.join("clean.txt"), STAGED_CLEAN).unwrap();
    git_add(repo, "clean.txt");
    git_commit(repo, "init");

    std::fs::write(repo.join(".env.provider"), STAGED_PROVIDER_TOKEN).unwrap();
    std::fs::write(repo.join("provider.txt"), STAGED_PROVIDER_TOKEN).unwrap();
    git_add(repo, ".env.provider");
    git_add(repo, "provider.txt");
    let output = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args([
            "scan",
            "--git-staged",
            "--daemon=on",
            "--dedup",
            "none",
            "--format",
            "json",
        ])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("scan staged blob aliases");
    assert_eq!(
        output.status.code(),
        Some(1),
        "credential-bearing alias must block; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("alias JSON report");
    let findings = report.as_array().expect("findings array");
    assert_eq!(
        findings.len(),
        2,
        "each exact staged source path must be scanned"
    );
    assert!(findings.iter().any(|finding| {
        finding["location"]["file_path"]
            .as_str()
            .is_some_and(|path| path.ends_with(".env.provider"))
            && finding["evidence"]["tier"] == "likely"
    }));
    assert!(findings.iter().any(|finding| {
        finding["location"]["file_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("provider.txt"))
            && finding["evidence"]["tier"] == "review"
    }));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("1 blob(s) scanned"),
        "aliases of one OID must retain one payload/receipt owner; stderr={stderr}"
    );
}

#[cfg(unix)]
#[test]
fn guard_commit_inline_suppression_uses_staged_bytes_not_worktree() {
    let daemon = DaemonGuard::start_cpu_embedded();
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_git_repo(repo);
    std::fs::write(repo.join("clean.txt"), STAGED_CLEAN).unwrap();
    git_add(repo, "clean.txt");
    git_commit(repo, "init");

    let staged = format!("// staged content\n{STAGED_PROVIDER_TOKEN}");
    std::fs::write(repo.join(".env.provider"), staged).unwrap();
    git_add(repo, ".env.provider");
    let divergent_worktree = format!("// keyhog:ignore\n{STAGED_PROVIDER_TOKEN}");
    std::fs::write(repo.join(".env.provider"), divergent_worktree).unwrap();

    let output = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["scan", "--git-staged", "--daemon=on", "--format", "json"])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("scan staged bytes with divergent worktree directive");
    assert_eq!(
        output.status.code(),
        Some(1),
        "a worktree-only inline directive must not suppress the staged finding; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("staged divergence JSON report");
    assert_eq!(report.as_array().map(Vec::len), Some(1));
    assert_eq!(report[0]["evidence"]["tier"], "likely");
}
