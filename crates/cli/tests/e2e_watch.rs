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
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Spawn `keyhog watch [extra] <dir>`, draining its stderr on a background thread
/// into a shared buffer so a caller can poll for a marker DETERMINISTICALLY
/// instead of racing a fixed sleep against ~900-detector debug-build compilation
/// (the old `sleep(300ms)` sampled an empty window, the compile hadn't reached
/// the banner yet (so a byte-length check passed vacuously on two empty outputs)).
fn spawn_watch_streaming(
    extra: &[&str],
    dir: &std::path::Path,
) -> (std::process::Child, Arc<Mutex<String>>) {
    let mut cmd = Command::new(binary());
    cmd.arg("watch").arg(dir);
    for a in extra {
        cmd.arg(a);
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keyhog watch");
    let buf = Arc::new(Mutex::new(String::new()));
    let stderr = child.stderr.take().expect("piped stderr");
    let sink = Arc::clone(&buf);
    thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => sink.lock().unwrap().push_str(&line),
            }
        }
    });
    (child, buf)
}

/// Poll `buf` (case-insensitively) for `marker` until it appears or `timeout`
/// elapses; returns whether the marker was seen.
fn stderr_contains_within(buf: &Arc<Mutex<String>>, marker: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        if buf.lock().unwrap().to_lowercase().contains(marker) {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        thread::sleep(Duration::from_millis(25));
    }
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

    // Non-quiet: once ~900-detector compilation finishes, watch.rs prints the
    // "    watching: <root>" banner to stderr. Poll for it deterministically (no
    // fixed-sleep race: Law 7) instead of sampling a fixed window the debug
    // compile blows through. Measure how long it took so the quiet window below
    // can be tied to THIS machine's compile latency.
    let (mut noisy, noisy_buf) = spawn_watch_streaming(&[], dir.path());
    let noisy_start = Instant::now();
    let noisy_saw_banner = stderr_contains_within(&noisy_buf, "watching", Duration::from_secs(60));
    let noisy_banner_latency = noisy_start.elapsed();
    let _ = noisy.kill();
    let _ = noisy.wait();
    assert!(
        noisy_saw_banner,
        "non-quiet watch must print the 'watching' status banner within 60s; got: {}",
        noisy_buf.lock().unwrap()
    );

    // Quiet: the banner is gated behind `if !args.quiet`, so it must NEVER appear.
    // Give quiet a window of the observed noisy banner latency + a healthy margin,
    // so a regression that (wrongly) printed the banner under --quiet WOULD have
    // done so within the window regardless of this machine's compile speed, then
    // assert the banner was suppressed. This is the real --quiet contract, not a
    // byte-length proxy (Law 6).
    let (mut quiet, quiet_buf) = spawn_watch_streaming(&["--quiet"], dir.path());
    let quiet_window = noisy_banner_latency + Duration::from_secs(3);
    let quiet_saw_banner = stderr_contains_within(&quiet_buf, "watching", quiet_window);
    let _ = quiet.kill();
    let _ = quiet.wait();
    assert!(
        !quiet_saw_banner,
        "--quiet must suppress the 'watching' status banner entirely; got quiet output: {}",
        quiet_buf.lock().unwrap()
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

    // Pin CPU so this watch behavior test is independent of host calibration.
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

    // Both findings must reach stdout (the first AND the second root).
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
