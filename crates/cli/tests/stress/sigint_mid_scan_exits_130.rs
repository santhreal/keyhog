//! WHY: Process cancellation and interrupt recovery contract (Row 52, Row 90):
//! SIGINT interruption must be handled safely at any pipeline stage, exiting with 130
//! without corrupting disk state or leaving surviving lock files, and the subsequent
//! full scan must run to completion and report the complete finding set.
//!
//! WHAT IT DOES NOT CATCH:
//! Uncatchable kernel signals such as SIGKILL (137).

use crate::support::{binary, workspace_detectors};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn sigint_mid_scan_exits_130() {
    let child = Command::new(binary())
        // Pin the deterministic CPU-SIMD backend so the scan actually RUNS long
        // enough to be interrupted mid-flight: an un-calibrated `auto` scan
        // fails closed (exit 2) before the 800 ms SIGINT, which would race the
        // signal contract this test exists to verify.
        .args(["scan", "--backend", "simd", "--daemon=off", "--profile"])
        .arg(workspace_detectors())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn scan");

    std::thread::sleep(Duration::from_millis(800));
    // SAFETY: sending SIGINT to our own child scan process.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }

    let output = child.wait_with_output().expect("wait for interrupted scan");
    assert_eq!(
        output.status.code(),
        Some(130),
        "SIGINT must map to exit 130; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Scan interrupted"),
        "stderr must announce interrupt; got: {stderr}"
    );
    assert!(
        stderr.contains(
            "profile outcome status=failed coverage=cancelled errors=1 exit=130 interruption=sigint"
        ),
        "profiled SIGINT must emit signal-safe interruption identity; got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn sigint_interrupted_cache_write_leaves_no_locks_and_subsequent_scan_succeeds() {
    let dir = TempDir::new().expect("tempdir");
    let cache_dir = TempDir::new().expect("cache tempdir");
    let cache_file = cache_dir.path().join("merkle.idx");

    // Plant a secret in the corpus
    std::fs::write(
        dir.path().join("secret.env"),
        "TOKEN=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\n",
    )
    .expect("write secret");

    // Create many dummy files to ensure scan runs across pipeline stages
    for i in 0..50 {
        std::fs::write(
            dir.path().join(format!("file_{i}.txt")),
            format!("dummy file content for worker iteration {i}\n"),
        )
        .expect("write dummy file");
    }

    // Spawn scan with incremental cache
    let child = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "cpu",
            "--daemon=off",
            "--incremental",
            "--incremental-cache",
            cache_file.to_str().unwrap(),
        ])
        .arg(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn scan");

    std::thread::sleep(Duration::from_millis(50));
    // SAFETY: sending SIGINT to our own child scan process.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }

    let output = child.wait_with_output().expect("wait for interrupted scan");
    assert_eq!(
        output.status.code(),
        Some(130),
        "SIGINT must exit 130; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify no surviving temporary lock files (*.lock, *.tmp) in cache directory
    if let Ok(entries) = std::fs::read_dir(cache_dir.path()) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.ends_with(".lock") && !name.ends_with(".tmp"),
                "surviving lock or tmp file found in cache dir: {name}"
            );
        }
    }

    // Subsequent full scan must run to completion and report the complete finding set
    let rescan = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "cpu",
            "--daemon=off",
            "--incremental",
            "--incremental-cache",
            cache_file.to_str().unwrap(),
            "--format",
            "json",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn subsequent scan");

    assert_eq!(
        rescan.status.code(),
        Some(1),
        "subsequent scan after SIGINT must succeed and report finding; stdout={}",
        String::from_utf8_lossy(&rescan.stdout)
    );
    assert!(
        String::from_utf8_lossy(&rescan.stdout).contains("github-classic-pat"),
        "subsequent scan must report all planted findings"
    );
}

#[cfg(not(unix))]
#[test]
fn sigint_mid_scan_exits_130() {
    // Windows has no SIGINT contract in STANDARD.md fleet table for this stress slice.
}
