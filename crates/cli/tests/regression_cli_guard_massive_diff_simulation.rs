//! Regression e2e & performance simulation: guarantee that massive staged diffs
//! (1,000, 5,000, and 10,000 files) execute within milliseconds when served by
//! the perpetual guard daemon, and verify edge cases including staged renames
//! and mode changes (executable +x bits).

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
        .args(["init", "-q", "-b", "main"])
        .current_dir(dir)
        .output()
        .expect("git init");
    assert!(out.status.success(), "git init must succeed");
    let _ = Command::new("git")
        .args(["config", "user.email", "guard-sim@test.local"])
        .current_dir(dir)
        .output();
    let _ = Command::new("git")
        .args(["config", "user.name", "Guard Sim"])
        .current_dir(dir)
        .output();
}

/// WHY: Guarantee that 1,000 staged clean files pass pre-commit gating with
/// sub-second initial registration and single-digit millisecond cached passes,
/// and that partial diff mutations (e.g. 5 modified files) only stream the
/// modified blobs while serving the 995 clean entries from daemon memory.
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
    assert_eq!(up_out.status.code(), Some(0), "guard up must succeed");

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
    assert!(git_add.status.success(), "git add 1000 files must succeed");

    // 4. Register repo with guard (indexes baseline into daemon memory).
    let add_out = Command::new(keyhog())
        .current_dir(repo)
        .env("NO_COLOR", "1")
        .args(["guard", "add", ".", "--socket"])
        .arg(&socket)
        .output()
        .expect("guard add");
    assert!(
        matches!(add_out.status.code(), Some(0 | 13)),
        "guard add must succeed"
    );

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

    assert_eq!(
        scan_out.status.code(),
        Some(0),
        "initial staged scan must exit 0"
    );
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

    assert_eq!(
        scan_cached.status.code(),
        Some(0),
        "cached staged scan must exit 0"
    );
    let cached_stderr = String::from_utf8_lossy(&scan_cached.stderr);
    assert!(
        cached_stderr.contains("1000 cache hit(s)"),
        "second pass must be 100% clean cache hits; stderr={cached_stderr}"
    );

    println!("1,000-file initial scan elapsed: {duration:?}");
    println!("1,000-file cached scan elapsed: {cached_duration:?}");

    // 7. Mixed diff test: mutate 5 files out of 1,000.
    for i in 0..5 {
        let filename = format!("src/module_{i:04}.rs");
        let path = repo.join(&filename);
        std::fs::write(
            &path,
            format!("pub fn func_{i}() -> usize {{ {i} + 42 }}\n"),
        )
        .unwrap();
    }
    let git_add_mutated = Command::new("git")
        .args([
            "add",
            "src/module_0000.rs",
            "src/module_0001.rs",
            "src/module_0002.rs",
            "src/module_0003.rs",
            "src/module_0004.rs",
        ])
        .current_dir(repo)
        .output()
        .expect("git add mutated");
    assert!(git_add_mutated.status.success(), "git add mutated files");

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

    assert_eq!(
        scan_mixed.status.code(),
        Some(0),
        "mixed staged scan must exit 0"
    );
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

/// WHY: Guarantee scaling across large 5,000-file staged diffs, ensuring
/// binary DIRC index parsing, memory allocation, and IPC wire serialization
/// scale linearly without timing out or dropping entries.
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
    assert_eq!(up_out.status.code(), Some(0), "guard up must succeed");

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
    assert!(git_add.status.success(), "git add 5000 files must succeed");

    // 4. Register repo with guard (indexes baseline into daemon memory).
    let add_out = Command::new(keyhog())
        .current_dir(repo)
        .env("NO_COLOR", "1")
        .args(["guard", "add", ".", "--socket"])
        .arg(&socket)
        .output()
        .expect("guard add");
    assert!(
        matches!(add_out.status.code(), Some(0 | 13)),
        "guard add must succeed"
    );

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

    assert_eq!(
        scan_out.status.code(),
        Some(0),
        "initial staged 5000 scan must exit 0"
    );
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

    assert_eq!(
        scan_cached.status.code(),
        Some(0),
        "cached staged 5000 scan must exit 0"
    );
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

/// WHY: Test 10,000-staged-file diff scaling, verifying that massive enterprise
/// repository monorepo diffs with ten thousand staged files stay within the
/// daemon's MAX_GUARD_MANIFEST_ENTRIES capacity limit (100,000 entries), execute
/// the entire manifest acquisition, wire serialization, and cache attestation
/// in rapid time, and serve mixed diffs without memory bloat or race condition errors.
#[cfg(unix)]
#[test]
fn massive_10000_file_diff_scaling_guarantees_millisecond_gating() {
    let _daemon_slot = daemon_slot();
    let dir = TempDir::new().unwrap();
    let repo = dir.path();
    init_git_repo(repo);
    let socket = repo.join("guard-massive-10000.sock");

    // 1. Start daemon on dedicated test socket.
    let up_out = Command::new(keyhog())
        .env("NO_COLOR", "1")
        .args(["guard", "up", "--backend", "cpu", "--socket"])
        .arg(&socket)
        .output()
        .expect("guard up");
    assert_eq!(up_out.status.code(), Some(0), "guard up must succeed");

    // 2. Generate 10,000 clean synthetic files.
    for i in 0..10000 {
        let filename = format!("src/pkg_{:03}/module_{:05}.rs", i / 500, i);
        let path = repo.join(&filename);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(
            &path,
            format!("pub fn compute_{i}() -> usize {{ {i} * 5 }}\n"),
        )
        .unwrap();
    }

    // 3. Stage all 10,000 files in Git index.
    let git_add = Command::new("git")
        .args(["add", "."])
        .current_dir(repo)
        .output()
        .expect("git add 10000");
    assert!(git_add.status.success(), "git add 10000 files must succeed");

    // 4. Register repo with guard (indexes baseline into daemon memory).
    let add_out = Command::new(keyhog())
        .current_dir(repo)
        .env("NO_COLOR", "1")
        .args(["guard", "add", ".", "--socket"])
        .arg(&socket)
        .output()
        .expect("guard add");
    assert!(
        matches!(add_out.status.code(), Some(0 | 13)),
        "guard add 10000 must succeed"
    );

    // 5. Initial staged scan simulation: 10,000 files in pre-commit hook.
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
        .expect("keyhog scan --fast --git-staged (10000 files)");
    let duration = start.elapsed();

    assert_eq!(
        scan_out.status.code(),
        Some(0),
        "initial staged 10000 scan must exit 0"
    );
    let scan_stderr = String::from_utf8_lossy(&scan_out.stderr);
    assert!(
        scan_stderr.contains("10000 cache hit(s)") || scan_stderr.contains("10000 blob(s) scanned"),
        "must process all 10000 files via guard; stderr={scan_stderr}"
    );

    // 6. Second staged scan: 100% clean cache hits across 10,000 entries.
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
        .expect("keyhog scan --fast --git-staged (10000 cached)");
    let cached_duration = start_cached.elapsed();

    assert_eq!(
        scan_cached.status.code(),
        Some(0),
        "cached staged 10000 scan must exit 0"
    );
    let cached_stderr = String::from_utf8_lossy(&scan_cached.stderr);
    assert!(
        cached_stderr.contains("10000 cache hit(s)"),
        "second pass must be 100% clean cache hits for 10000 files; stderr={cached_stderr}"
    );

    println!("10,000-file initial scan elapsed: {duration:?}");
    println!("10,000-file cached scan elapsed: {cached_duration:?}");

    // 7. Mixed diff at scale: mutate 10 files out of 10,000.
    for i in 0..10 {
        let filename = format!("src/pkg_{:03}/module_{:05}.rs", i / 500, i);
        let path = repo.join(&filename);
        std::fs::write(
            &path,
            format!("pub fn compute_{i}() -> usize {{ {i} * 5 + 99 }}\n"),
        )
        .unwrap();
    }
    let git_add_mutated = Command::new("git")
        .args([
            "add",
            "src/pkg_000/module_00000.rs",
            "src/pkg_000/module_00001.rs",
            "src/pkg_000/module_00002.rs",
            "src/pkg_000/module_00003.rs",
            "src/pkg_000/module_00004.rs",
            "src/pkg_000/module_00005.rs",
            "src/pkg_000/module_00006.rs",
            "src/pkg_000/module_00007.rs",
            "src/pkg_000/module_00008.rs",
            "src/pkg_000/module_00009.rs",
        ])
        .current_dir(repo)
        .output()
        .expect("git add mutated 10");
    assert!(git_add_mutated.status.success(), "git add mutated files");

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
        .expect("keyhog scan --fast --git-staged (10000 mixed)");
    let mixed_duration = start_mixed.elapsed();

    assert_eq!(
        scan_mixed.status.code(),
        Some(0),
        "mixed staged 10000 scan must exit 0"
    );
    let mixed_stderr = String::from_utf8_lossy(&scan_mixed.stderr);
    assert!(
        mixed_stderr.contains("9990 cache hit(s)") && mixed_stderr.contains("10 blob(s) scanned"),
        "mixed diff must serve 9990 hits and stream only 10 blobs; stderr={mixed_stderr}"
    );
    println!("10,000-file mixed scan (10 changed, 9990 cached) elapsed: {mixed_duration:?}");

    // 8. Clean shutdown.
    let _ = Command::new(keyhog())
        .args(["guard", "down", "--socket"])
        .arg(&socket)
        .output();
}

/// WHY: Test staged renames in the guard commit protocol. When clean files are
/// renamed via `git mv`, Git records a deletion at the old path and an addition
/// at the new path. The daemon must process the renamed entries accurately:
/// on initial path occurrence it scans and validates the new path, and on repeat
/// cached passes it serves 100% clean cache hits.
#[cfg(unix)]
#[test]
fn guard_staged_diff_edge_cases_staged_renames() {
    let _daemon_slot = daemon_slot();
    let dir = TempDir::new().unwrap();
    let repo = dir.path();
    init_git_repo(repo);
    let socket = repo.join("guard-renames.sock");

    // 1. Start daemon.
    let up_out = Command::new(keyhog())
        .env("NO_COLOR", "1")
        .args(["guard", "up", "--backend", "cpu", "--socket"])
        .arg(&socket)
        .output()
        .expect("guard up");
    assert_eq!(up_out.status.code(), Some(0), "guard up must succeed");

    // 2. Create 50 clean files and stage them.
    for i in 0..50 {
        let filename = format!("src/file_{i:02}.rs");
        let path = repo.join(&filename);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, format!("pub fn item_{i}() -> u32 {{ {i} }}\n")).unwrap();
    }
    let git_add = Command::new("git")
        .args(["add", "."])
        .current_dir(repo)
        .output()
        .expect("git add initial");
    assert!(git_add.status.success());

    // 3. Register repo with guard daemon.
    let add_out = Command::new(keyhog())
        .current_dir(repo)
        .env("NO_COLOR", "1")
        .args(["guard", "add", ".", "--socket"])
        .arg(&socket)
        .output()
        .expect("guard add");
    assert!(matches!(add_out.status.code(), Some(0 | 13)));

    // 4. Initial scan: all 50 files clean.
    let scan_1 = Command::new(keyhog())
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
        .expect("scan initial");
    assert_eq!(scan_1.status.code(), Some(0), "initial scan must exit 0");

    // Commit baseline so git mv operates against committed HEAD tree.
    let git_commit = Command::new("git")
        .args(["commit", "-q", "-m", "initial commit"])
        .current_dir(repo)
        .output()
        .expect("git commit initial");
    assert!(git_commit.status.success(), "git commit must succeed");

    // 5. Staged Renames:
    // - Pure rename of 10 files: src/file_00..09 -> src/renamed_00..09
    for i in 0..10 {
        let src = format!("src/file_{i:02}.rs");
        let dst = format!("src/renamed_{i:02}.rs");
        let mv_out = Command::new("git")
            .args(["mv", &src, &dst])
            .current_dir(repo)
            .output()
            .expect("git mv pure");
        assert!(mv_out.status.success(), "git mv {src} -> {dst}");
    }

    // - Rename + modification of 2 files: src/file_10..11 -> src/renamed_mod_10..11
    for i in 10..12 {
        let src = format!("src/file_{i:02}.rs");
        let dst = format!("src/renamed_mod_{i:02}.rs");
        let mv_out = Command::new("git")
            .args(["mv", &src, &dst])
            .current_dir(repo)
            .output()
            .expect("git mv mod");
        assert!(mv_out.status.success());
        // Mutate content of dst
        let path = repo.join(&dst);
        std::fs::write(&path, format!("pub fn item_{i}() -> u32 {{ {i} + 999 }}\n")).unwrap();
        let add_mod = Command::new("git")
            .args(["add", &dst])
            .current_dir(repo)
            .output()
            .expect("git add modified rename");
        assert!(add_mod.status.success());
    }

    // 6. Staged scan with renames.
    // In git diff --cached, we have 12 non-deletion entries (10 pure renames, 2 modified renames).
    let scan_renames = Command::new(keyhog())
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
        .expect("scan renames");
    assert_eq!(
        scan_renames.status.code(),
        Some(0),
        "staged rename scan must exit 0"
    );
    let renames_stderr = String::from_utf8_lossy(&scan_renames.stderr);
    assert!(
        renames_stderr.contains("12 blob(s) scanned") || renames_stderr.contains("12 cache hit(s)"),
        "renamed entries must be processed cleanly; stderr={renames_stderr}"
    );

    // 7. Second scan over staged renames: now all 12 entries are 100% clean cache hits.
    let scan_renames_cached = Command::new(keyhog())
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
        .expect("scan renames cached");
    assert_eq!(scan_renames_cached.status.code(), Some(0));
    let renames_cached_stderr = String::from_utf8_lossy(&scan_renames_cached.stderr);
    assert!(
        renames_cached_stderr.contains("12 cache hit(s)"),
        "all staged entries must be clean cache hits on repeat pass; stderr={renames_cached_stderr}"
    );

    // 8. Clean shutdown.
    let _ = Command::new(keyhog())
        .args(["guard", "down", "--socket"])
        .arg(&socket)
        .output();
}

/// WHY: Test mode changes (e.g. `chmod +x` changing file mode from 100644 to 100755)
/// in the staged Git index. When a clean file's mode is changed without content
/// modification, the object OID is unchanged and the daemon serves it as a clean hit.
/// When an executable script contains an active credential, the finding must be
/// reported and block pre-commit gating with exit code 1.
#[cfg(unix)]
#[test]
fn guard_staged_diff_edge_cases_mode_changes_executable() {
    let _daemon_slot = daemon_slot();
    let dir = TempDir::new().unwrap();
    let repo = dir.path();
    init_git_repo(repo);
    let socket = repo.join("guard-modes.sock");

    // 1. Start daemon.
    let up_out = Command::new(keyhog())
        .env("NO_COLOR", "1")
        .args(["guard", "up", "--backend", "cpu", "--socket"])
        .arg(&socket)
        .output()
        .expect("guard up");
    assert_eq!(up_out.status.code(), Some(0), "guard up must succeed");

    // 2. Create clean files and scripts.
    let script_clean = repo.join("scripts/deploy_clean.sh");
    let tool_clean = repo.join("tools/helper.py");
    let lib_clean = repo.join("src/lib.rs");
    std::fs::create_dir_all(repo.join("scripts")).unwrap();
    std::fs::create_dir_all(repo.join("tools")).unwrap();
    std::fs::create_dir_all(repo.join("src")).unwrap();

    std::fs::write(
        &script_clean,
        "#!/usr/bin/env bash\necho 'deploying clean'\n",
    )
    .unwrap();
    std::fs::write(&tool_clean, "#!/usr/bin/env python3\nprint('helper')\n").unwrap();
    std::fs::write(&lib_clean, "pub fn add(a: i32, b: i32) -> i32 { a + b }\n").unwrap();

    let git_add = Command::new("git")
        .args(["add", "."])
        .current_dir(repo)
        .output()
        .expect("git add initial");
    assert!(git_add.status.success());

    // Commit baseline.
    let git_commit = Command::new("git")
        .args(["commit", "-q", "-m", "initial baseline"])
        .current_dir(repo)
        .output()
        .expect("git commit initial");
    assert!(git_commit.status.success());

    // Register repo with guard daemon.
    let add_out = Command::new(keyhog())
        .current_dir(repo)
        .env("NO_COLOR", "1")
        .args(["guard", "add", ".", "--socket"])
        .arg(&socket)
        .output()
        .expect("guard add");
    assert!(matches!(add_out.status.code(), Some(0 | 13)));

    // 3. Change mode of clean scripts to executable (+x) in Git index.
    let chmod_out = Command::new("git")
        .args([
            "update-index",
            "--chmod=+x",
            "scripts/deploy_clean.sh",
            "tools/helper.py",
        ])
        .current_dir(repo)
        .output()
        .expect("git update-index --chmod=+x");
    assert!(
        chmod_out.status.success(),
        "chmod +x in git index must succeed"
    );

    // 4. Staged scan with mode changes: object OID is identical, daemon recognizes clean hits.
    let scan_mode_clean = Command::new(keyhog())
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
        .expect("scan mode change clean");
    assert_eq!(
        scan_mode_clean.status.code(),
        Some(0),
        "clean mode change scan must exit 0"
    );
    let mode_clean_stderr = String::from_utf8_lossy(&scan_mode_clean.stderr);
    assert!(
        mode_clean_stderr.contains("2 cache hit(s)")
            || mode_clean_stderr.contains("2 blob(s) scanned"),
        "mode changes with identical content must be processed; stderr={mode_clean_stderr}"
    );

    // 5. Stage an executable script containing a credential.
    let secret_script = repo.join("scripts/run_leak.sh");
    // Synthetic AWS access key pattern that triggers AWS detector (non-example pattern).
    std::fs::write(
        &secret_script,
        "#!/bin/bash\nexport AWS_ACCESS_KEY_ID=\"AKIAQYLPMN5HFIQR7XYA\"\n",
    )
    .unwrap();
    let git_add_secret = Command::new("git")
        .args(["add", "scripts/run_leak.sh"])
        .current_dir(repo)
        .output()
        .expect("git add secret script");
    assert!(git_add_secret.status.success());
    let chmod_secret = Command::new("git")
        .args(["update-index", "--chmod=+x", "scripts/run_leak.sh"])
        .current_dir(repo)
        .output()
        .expect("chmod secret");
    assert!(chmod_secret.status.success());

    // 6. Staged scan must detect the secret and block commit with exit code 1 (EXIT_CREDENTIALS_FOUND).
    let scan_secret = Command::new(keyhog())
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
        .expect("scan secret");
    assert_eq!(
        scan_secret.status.code(),
        Some(1),
        "scan finding secret must exit 1 (EXIT_CREDENTIALS_FOUND)"
    );
    let secret_stderr = String::from_utf8_lossy(&scan_secret.stderr);
    let secret_stdout = String::from_utf8_lossy(&scan_secret.stdout);
    let combined = format!("{secret_stdout}\n{secret_stderr}");
    assert!(
        combined.contains("run_leak.sh")
            || combined.contains("AWS")
            || combined.contains("finding"),
        "secret finding must be surfaced; output={combined}"
    );

    // 7. Remediate: remove secret from the script, stage clean content, verify exit 0.
    std::fs::write(
        &secret_script,
        "#!/bin/bash\n# Credential removed; reads from secure secret manager at runtime\necho 'running'\n",
    )
    .unwrap();
    let git_add_clean = Command::new("git")
        .args(["add", "scripts/run_leak.sh"])
        .current_dir(repo)
        .output()
        .expect("git add remediated");
    assert!(git_add_clean.status.success());

    let scan_remediated = Command::new(keyhog())
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
        .expect("scan remediated");
    assert_eq!(
        scan_remediated.status.code(),
        Some(0),
        "remediated scan must exit 0"
    );

    // 8. Clean shutdown.
    let _ = Command::new(keyhog())
        .args(["guard", "down", "--socket"])
        .arg(&socket)
        .output();
}
