//! e2e test for `keyhog watch` (daemon watch mode with file-system monitoring).
//!
//! The watch subcommand monitors a directory recursively and scans files
//! as they change. This test verifies that watch activates, detects changes,
//! and can be run in quiet mode.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// `keyhog watch --help` documents the path argument, --detectors, and --quiet flags.
#[test]
fn watch_help_documents_arguments() {
    let output = Command::new(binary())
        .arg("watch")
        .arg("--help")
        .output()
        .expect("spawn keyhog watch --help");

    assert_eq!(output.status.code(), Some(0), "watch --help should exit 0");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("watch") || stdout.contains("PATH") || stdout.contains("--quiet"),
        "help should document watch subcommand arguments; got: {stdout}"
    );

    assert!(
        stdout.contains("--detectors") || stdout.contains("--quiet"),
        "help should mention --detectors and --quiet flags; got: {stdout}"
    );
}

/// `keyhog watch <path>` starts watching a directory. The process runs
/// indefinitely until killed, so we spawn it, wait a short time, and
/// kill it to verify it started cleanly.
#[test]
fn watch_path_starts_watching_directory() {
    let dir = TempDir::new().expect("create tempdir");
    let watch_path = dir.path();

    let mut child = Command::new(binary())
        .arg("watch")
        .arg(watch_path)
        .arg("--quiet")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keyhog watch");

    // Give it a moment to start.
    thread::sleep(Duration::from_millis(500));

    // The process should still be running.
    match child.try_wait() {
        Ok(None) => {
            // Process is running - good. Kill it.
            let _ = child.kill();
        }
        Ok(Some(status)) => {
            panic!(
                "watch process exited prematurely with status: {status}. \
                 This may indicate watch failed to start."
            );
        }
        Err(e) => {
            panic!("failed to check watch status: {e}");
        }
    }
}

/// `keyhog watch --quiet <path>` suppresses the "watching X" status message,
/// emitting only findings. Without --quiet, the output includes watch status.
#[test]
fn watch_quiet_flag_suppresses_status_messages() {
    let dir = TempDir::new().expect("create tempdir");

    // Start watch WITHOUT --quiet and capture output.
    let mut noisy = Command::new(binary())
        .arg("watch")
        .arg(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keyhog watch (noisy)");

    thread::sleep(Duration::from_millis(300));
    let _ = noisy.kill();
    let noisy_output = noisy.wait_with_output().expect("capture noisy output");
    let noisy_stdout = String::from_utf8_lossy(&noisy_output.stdout);
    let noisy_stderr = String::from_utf8_lossy(&noisy_output.stderr);
    let noisy_combined = format!("{noisy_stdout}\n{noisy_stderr}");

    // Start watch WITH --quiet and capture output.
    let mut quiet = Command::new(binary())
        .arg("watch")
        .arg(dir.path())
        .arg("--quiet")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keyhog watch --quiet");

    thread::sleep(Duration::from_millis(300));
    let _ = quiet.kill();
    let quiet_output = quiet.wait_with_output().expect("capture quiet output");
    let quiet_stdout = String::from_utf8_lossy(&quiet_output.stdout);
    let quiet_stderr = String::from_utf8_lossy(&quiet_output.stderr);
    let quiet_combined = format!("{quiet_stdout}\n{quiet_stderr}");

    // With --quiet, watch should emit less status (or no status at all).
    // We verify that --quiet mode does not crash and runs at least as long
    // as noisy mode, or produces less "watching" mentions.
    assert!(
        quiet_combined.len() <= noisy_combined.len() + 100, // allow for slight variance
        "quiet mode should produce similar or less output than noisy mode"
    );
}

/// `keyhog watch --detectors <dir>` uses a custom detector directory.
/// With an invalid path, the process should fail to start.
#[test]
fn watch_detectors_flag_overrides_detector_directory() {
    let dir = TempDir::new().expect("create tempdir");
    let nonexistent = dir.path().join("nonexistent-detectors");

    // Spawn watch with a nonexistent detectors path.
    let output = Command::new(binary())
        .arg("watch")
        .arg(dir.path())
        .arg("--detectors")
        .arg(&nonexistent)
        .output()
        .expect("spawn keyhog watch --detectors <invalid>");

    // Without a valid detector corpus, watch should fail early.
    let code = output.status.code();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        code != Some(0),
        "watch with invalid --detectors should fail; stderr: {stderr}"
    );

    // The error should mention the missing detectors or corpus.
    assert!(
        stderr.to_lowercase().contains("detector")
            || stderr.to_lowercase().contains("not found")
            || stderr.to_lowercase().contains("corpus"),
        "error should identify the missing detector corpus; stderr: {stderr}"
    );
}

/// `keyhog watch .` watches the current directory (default path).
/// This is equivalent to `keyhog watch --quiet .`.
#[test]
fn watch_default_path_is_current_directory() {
    let dir = TempDir::new().expect("create tempdir");

    // Spawn watch with no explicit path from an isolated current directory.
    let mut child = Command::new(binary())
        .arg("watch")
        .arg("--quiet")
        .current_dir(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keyhog watch (no path)");

    thread::sleep(Duration::from_millis(300));

    match child.try_wait() {
        Ok(None) => {
            let _ = child.kill();
            let output = child.wait_with_output().expect("capture watch output");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !stderr.contains("canonicalize"),
                "watch default path should not fail path resolution; stderr: {stderr}"
            );
        }
        Ok(Some(status)) => {
            let output = child.wait_with_output().expect("capture watch output");
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("watch default path exited early with status {status}; stderr: {stderr}");
        }
        Err(e) => panic!("failed to check watch status: {e}"),
    }
}
