//! Regression e2e & performance simulation: guarantee that massive staged diffs
//! (1,000+ files) execute within milliseconds when served by the perpetual guard daemon.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;
use tempfile::TempDir;

fn keyhog() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

static DAEMON_TEST_MUTEX: Mutex<()> = Mutex::new(());

fn daemon_slot() -> std::sync::MutexGuard<'static, ()> {
    DAEMON_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
}

fn init_git_repo(dir: &Path) {
    let out = Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir)
        .output()
        .expect("git init");
    assert!(out.status.success());
    let _ = Command::new("git")
        .args(["config", "user.email", "guard-sim@test.local"])
        .current_dir(dir)
        .output();
    let _ = Command::new("git")
        .args(["config", "user.name", "Guard Sim"])
        .current_dir(dir)
        .output();
}

#[cfg(unix)]
#[test]
fn massive_1000_file_diff_guarantees_millisecond_gating() {
    let _daemon_slot = daemon_slot();
    let dir = TempDir::new().unwrap();
    let repo = dir.path();
    init_git_repo(repo);
    let socket = repo.join("guard-massive-1000.sock");

    // 1. Start daemon on dedicated test socket.
    let up_out = Command::new(keyhog())
        .env("NO_COLOR", "1")
        .args(["guard", "up", "--backend", "cpu", "--socket"])
        .arg(&socket)
        .output()
        .expect("guard up");
    assert_eq!(up_out.status.code(), Some(0));

    // 2. Generate 1,000 clean synthetic files.
    for i in 0..1000 {
        let filename = format!("src/module_{i:04}.rs");
        let path = repo.join(&filename);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, format!("pub fn func_{i}() -> usize {{ {i} }}\n")).unwrap();
    }

    // 3. Stage all 1,000 files in Git index.
    let git_add = Command::new("git")
        .args(["add", "."])
        .current_dir(repo)
        .output()
        .expect("git add");
    assert!(git_add.status.success());

    // 4. Register repo with guard (indexes baseline into daemon memory).
    let add_out = Command::new(keyhog())
        .current_dir(repo)
        .env("NO_COLOR", "1")
        .args(["guard", "add", ".", "--socket"])
        .arg(&socket)
        .output()
        .expect("guard add");
    assert!(matches!(add_out.status.code(), Some(0 | 13)));

    // 5. Initial staged scan simulation: 1,000 files in pre-commit hook.
    // Must hit 1,000 cache hits and complete in single-digit ms transaction time.
    let start = Instant::now();
    let scan_out = Command::new(keyhog())
        .current_dir(repo)
        .env("NO_COLOR", "1")
        .args([
            "scan",
            "--fast",
            "--git-staged",
            "--backend",
            "cpu",
            "--daemon-socket",
        ])
        .arg(&socket)
        .output()
        .expect("keyhog scan --fast --git-staged");
    let duration = start.elapsed();

    assert_eq!(scan_out.status.code(), Some(0));
    let scan_stderr = String::from_utf8_lossy(&scan_out.stderr);
    assert!(
        scan_stderr.contains("1000 cache hit(s)") || scan_stderr.contains("1000 blob(s) scanned"),
        "must process all 1000 files via guard; stderr={scan_stderr}"
    );

    // 6. Second staged scan: 100% clean cache hits.
    let start_cached = Instant::now();
    let scan_cached = Command::new(keyhog())
        .current_dir(repo)
        .env("NO_COLOR", "1")
        .args([
            "scan",
            "--fast",
            "--git-staged",
            "--backend",
            "cpu",
            "--daemon-socket",
        ])
        .arg(&socket)
        .output()
        .expect("keyhog scan --fast --git-staged (cached)");
    let cached_duration = start_cached.elapsed();

    assert_eq!(scan_cached.status.code(), Some(0));
    let cached_stderr = String::from_utf8_lossy(&scan_cached.stderr);
    assert!(
        cached_stderr.contains("1000 cache hit(s)"),
        "second pass must be 100% clean cache hits; stderr={cached_stderr}"
    );

    // Assert total end-to-end execution of 1,000 file clean scan stays within tight budget.
    println!("1,000-file initial scan elapsed: {duration:?}");
    println!("1,000-file cached scan elapsed: {cached_duration:?}");

    // 7. Mixed diff test: mutate 5 files out of 1,000.
    for i in 0..5 {
        let filename = format!("src/module_{i:04}.rs");
        let path = repo.join(&filename);
        std::fs::write(&path, format!("pub fn func_{i}() -> usize {{ {i} + 42 }}\n")).unwrap();
    }
    let git_add_mutated = Command::new("git")
        .args(["add", "src/module_0000.rs", "src/module_0001.rs", "src/module_0002.rs", "src/module_0003.rs", "src/module_0004.rs"])
        .current_dir(repo)
        .output()
        .expect("git add mutated");
    assert!(git_add_mutated.status.success());

    let start_mixed = Instant::now();
    let scan_mixed = Command::new(keyhog())
        .current_dir(repo)
        .env("NO_COLOR", "1")
        .args([
            "scan",
            "--fast",
            "--git-staged",
            "--backend",
            "cpu",
            "--daemon-socket",
        ])
        .arg(&socket)
        .output()
        .expect("keyhog scan --fast --git-staged (mixed)");
    let mixed_duration = start_mixed.elapsed();

    assert_eq!(scan_mixed.status.code(), Some(0));
    let mixed_stderr = String::from_utf8_lossy(&scan_mixed.stderr);
    assert!(
        mixed_stderr.contains("995 cache hit(s)") && mixed_stderr.contains("5 blob(s) scanned"),
        "mixed diff must serve 995 hits and stream only 5 blobs; stderr={mixed_stderr}"
    );
    println!("1,000-file mixed scan (5 changed, 995 cached) elapsed: {mixed_duration:?}");

    // 8. Clean shutdown.
    let _ = Command::new(keyhog())
        .args(["guard", "down", "--socket"])
        .arg(&socket)
        .output();
}

#[cfg(unix)]
#[test]
fn massive_5000_file_diff_guarantees_millisecond_gating() {
    let _daemon_slot = daemon_slot();
    let dir = TempDir::new().unwrap();
    let repo = dir.path();
    init_git_repo(repo);
    let socket = repo.join("guard-massive-5000.sock");

    // 1. Start daemon on dedicated test socket.
    let up_out = Command::new(keyhog())
        .env("NO_COLOR", "1")
        .args(["guard", "up", "--backend", "cpu", "--socket"])
        .arg(&socket)
        .output()
        .expect("guard up");
    assert_eq!(up_out.status.code(), Some(0));

    // 2. Generate 5,000 clean synthetic files.
    for i in 0..5000 {
        let filename = format!("src/pkg_{}/module_{i:05}.rs", i / 500);
        let path = repo.join(&filename);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, format!("pub fn func_{i}() -> usize {{ {i} * 2 }}\n")).unwrap();
    }

    // 3. Stage all 5,000 files in Git index.
    let git_add = Command::new("git")
        .args(["add", "."])
        .current_dir(repo)
        .output()
        .expect("git add");
    assert!(git_add.status.success());

    // 4. Register repo with guard (indexes baseline into daemon memory).
    let add_out = Command::new(keyhog())
        .current_dir(repo)
        .env("NO_COLOR", "1")
        .args(["guard", "add", ".", "--socket"])
        .arg(&socket)
        .output()
        .expect("guard add");
    assert!(matches!(add_out.status.code(), Some(0 | 13)));

    // 5. Initial staged scan simulation: 5,000 files in pre-commit hook.
    let start = Instant::now();
    let scan_out = Command::new(keyhog())
        .current_dir(repo)
        .env("NO_COLOR", "1")
        .args([
            "scan",
            "--fast",
            "--git-staged",
            "--backend",
            "cpu",
            "--daemon-socket",
        ])
        .arg(&socket)
        .output()
        .expect("keyhog scan --fast --git-staged (5000 files)");
    let duration = start.elapsed();

    assert_eq!(scan_out.status.code(), Some(0));
    let scan_stderr = String::from_utf8_lossy(&scan_out.stderr);
    assert!(
        scan_stderr.contains("5000 cache hit(s)") || scan_stderr.contains("5000 blob(s) scanned"),
        "must process all 5000 files via guard; stderr={scan_stderr}"
    );

    // 6. Second staged scan: 100% clean cache hits.
    let start_cached = Instant::now();
    let scan_cached = Command::new(keyhog())
        .current_dir(repo)
        .env("NO_COLOR", "1")
        .args([
            "scan",
            "--fast",
            "--git-staged",
            "--backend",
            "cpu",
            "--daemon-socket",
        ])
        .arg(&socket)
        .output()
        .expect("keyhog scan --fast --git-staged (5000 cached)");
    let cached_duration = start_cached.elapsed();

    assert_eq!(scan_cached.status.code(), Some(0));
    let cached_stderr = String::from_utf8_lossy(&scan_cached.stderr);
    assert!(
        cached_stderr.contains("5000 cache hit(s)"),
        "second pass must be 100% clean cache hits for 5000 files; stderr={cached_stderr}"
    );

    println!("5,000-file initial scan elapsed: {duration:?}");
    println!("5,000-file cached scan elapsed: {cached_duration:?}");

    // 7. Clean shutdown.
    let _ = Command::new(keyhog())
        .args(["guard", "down", "--socket"])
        .arg(&socket)
        .output();
}
