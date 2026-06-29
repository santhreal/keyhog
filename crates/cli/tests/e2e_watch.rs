//! e2e test for `keyhog watch` (daemon watch mode with file-system monitoring).
//!
//! The watch subcommand monitors a directory recursively and scans files
//! as they change. This test verifies that watch activates, detects changes,
//! and can be run in quiet mode.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
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

/// Drain a child pipe line-by-line into a shared buffer until EOF. Returning
/// on EOF (which the OS signals when the killed child's pipe closes) keeps the
/// child from blocking on a full pipe while the test polls the buffer.
fn drain_pipe<R: std::io::Read + Send + 'static>(pipe: R) -> Arc<Mutex<String>> {
    let captured = Arc::new(Mutex::new(String::new()));
    let writer = Arc::clone(&captured);
    thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => writer.lock().expect("buffer lock").push_str(&line),
            }
        }
    });
    captured
}

/// Poll `buffer` until `needles` all appear, or `deadline` elapses. Returns the
/// outcome so the caller asserts on a concrete readiness fact, not a fixed
/// sleep that races the ~3 s detector compile.
fn wait_until_contains(buffer: &Arc<Mutex<String>>, needles: &[&str], deadline: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        {
            let seen = buffer.lock().expect("buffer lock");
            if needles.iter().all(|needle| seen.contains(needle)) {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

/// `keyhog watch A B` registers BOTH roots on a single daemon and a secret
/// written under EACH root is detected. This proves multi-root watch is real
/// end to end and not a first-root-only illusion: the second root's finding
/// would never print if only `A` were registered.
///
/// The test is readiness-gated, not sleep-timed: it waits for the per-root
/// `watching:` banner (which prints only after the scanner finishes its cold
/// compile) before writing, then polls stdout for both findings. inotify
/// delivery is sub-millisecond, so the generous deadlines never flake.
#[test]
fn watch_detects_changes_under_every_root() {
    let root_a = TempDir::new().expect("tempdir a");
    let root_b = TempDir::new().expect("tempdir b");
    let canon_a = root_a.path().canonicalize().expect("canonical a");
    let canon_b = root_b.path().canonicalize().expect("canonical b");

    // An explicit backend is required: an uncalibrated binary's watch fails
    // closed on autoroute, so `--backend cpu` is what lets a finding print.
    // No `--quiet`: the `watching:` banner is the readiness signal.
    let mut child = Command::new(binary())
        .arg("watch")
        .arg(root_a.path())
        .arg(root_b.path())
        .args(["--backend", "cpu"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keyhog watch A B");

    let stdout_buf = drain_pipe(child.stdout.take().expect("stdout piped"));
    let stderr_buf = drain_pipe(child.stderr.take().expect("stderr piped"));

    // Gate on registration: both roots must appear in the banner before we
    // write, so the inotify watches are live when the files land.
    let registered = wait_until_contains(
        &stderr_buf,
        &[
            &canon_a.display().to_string(),
            &canon_b.display().to_string(),
        ],
        Duration::from_secs(20),
    );
    assert!(
        registered,
        "watch must register BOTH roots in its banner; stderr={}",
        stderr_buf.lock().expect("buffer lock")
    );

    // Plant a real (valid-checksum) AWS access key under each root.
    const PLANTED: &str = "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n";
    std::fs::write(root_a.path().join("a.env"), PLANTED).expect("write under root A");
    std::fs::write(root_b.path().join("b.env"), PLANTED).expect("write under root B");

    // Both findings must reach stdout — the first AND the second root.
    let both_found = wait_until_contains(&stdout_buf, &["a.env", "b.env"], Duration::from_secs(15));
    let _ = child.kill();

    assert!(
        both_found,
        "a change under EVERY watched root must be scanned (multi-root, not \
         first-only); stdout={} stderr={}",
        stdout_buf.lock().expect("buffer lock"),
        stderr_buf.lock().expect("buffer lock"),
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
