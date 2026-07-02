//! Regression coverage for `keyhog watch --quiet` verbosity.
//!
//! `--quiet` is the single verbosity knob on the `watch` daemon: it suppresses
//! the startup *banner* (the "👁 keyhog watch (☰ N detectors compiled) /
//! watching: <root> / Ctrl-C to exit" block, all on STDERR) while leaving the
//! finding stream on STDOUT byte-for-byte unchanged. This file pins that
//! contract with concrete stdout/stderr contrasts observed from the real
//! binary, not shape checks:
//!
//!   * quiet stderr is EMPTY (0 bytes) even while findings stream;
//!   * noisy stderr carries the banner and the canonical watched-root path;
//!   * the STDOUT finding line is identical under both modes
//!     (`🔍 aws-access-key <path>:<line> Critical (1.00)  AK...YA`);
//!   * the credential is redacted to `AK...YA`, never the full key;
//!   * an invalid `--detectors` fails with exit code 2 regardless of `--quiet`.
//!
//! Host-independence: every scanning invocation forces `--backend cpu`. An
//! uncalibrated binary's `watch` fails closed on autoroute, so `--backend cpu`
//! is what lets a finding print AND guarantees the CPU path on any host (no
//! accelerator assumption). Readiness is gated on observable output (the banner
//! for noisy mode; a stdout finding for quiet mode), never a fixed sleep.

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A real AWS access key id with a valid checksum, so `aws-access-key` fires
/// with confidence 1.00 (checksum-verified maximum, host-independent) and is
/// not dropped by keyhog's checksum gate.
const AWS_KEY: &str = "AKIAQYLPMN5HFIQR7XYA";

/// `redact("AKIAQYLPMN5HFIQR7XYA")` — 20 ASCII chars, edge = (20/8).clamp(1,4)
/// = 2 — yields first-2 + "..." + last-2. Deterministic, host-independent.
const REDACTED: &str = "AK...YA";

/// Drain a child pipe line-by-line into a shared buffer until EOF (the OS
/// closes the pipe when the killed child exits), so the child never blocks on a
/// full pipe while the test polls the buffer.
fn drain_pipe<R: Read + Send + 'static>(pipe: R) -> Arc<Mutex<String>> {
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

/// Poll `buffer` until every needle appears, or `deadline` elapses.
fn wait_until_contains(buffer: &Arc<Mutex<String>>, needles: &[&str], deadline: Duration) -> bool {
    let start = Instant::now();
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

fn snapshot(buffer: &Arc<Mutex<String>>) -> String {
    buffer.lock().expect("buffer lock").clone()
}

/// Extract the first captured line containing `needle` (newline stripped).
fn line_containing(buffer: &Arc<Mutex<String>>, needle: &str) -> Option<String> {
    let seen = buffer.lock().expect("buffer lock");
    seen.lines()
        .find(|l| l.contains(needle))
        .map(|l| l.to_string())
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Spawn `keyhog watch <root> --backend cpu [--quiet]` with piped std streams.
fn spawn_watch(
    root: &std::path::Path,
    quiet: bool,
) -> (Child, Arc<Mutex<String>>, Arc<Mutex<String>>) {
    let mut cmd = Command::new(binary());
    cmd.arg("watch")
        .arg(root)
        .args(["--backend", "cpu"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if quiet {
        cmd.arg("--quiet");
    }
    let mut child = cmd.spawn().expect("spawn keyhog watch");
    let out = drain_pipe(child.stdout.take().expect("stdout piped"));
    let err = drain_pipe(child.stderr.take().expect("stderr piped"));
    (child, out, err)
}

/// Rewrite `path` with the AWS key on line `key_line` (1-based) plus a changing
/// nonce, repeatedly, until `stdout` reports the finding or the deadline hits.
/// The nonce makes each write byte-distinct so the content-dedup never blocks,
/// and the loop tolerates the cold detector compile without a fixed sleep: once
/// the watcher is live, the next write is caught. Returns whether the finding
/// appeared.
fn plant_until_found(
    path: &std::path::Path,
    key_line: usize,
    stdout: &Arc<Mutex<String>>,
    deadline: Duration,
) -> bool {
    let leading = "# pad\n".repeat(key_line.saturating_sub(1));
    let start = Instant::now();
    let mut nonce = 0u64;
    while start.elapsed() < deadline {
        nonce += 1;
        let body = format!("{leading}AWS_ACCESS_KEY_ID = \"{AWS_KEY}\"\n# nonce {nonce}\n");
        std::fs::write(path, body).expect("write planted secret");
        if wait_until_contains(stdout, &["aws-access-key"], Duration::from_millis(400)) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------

/// `watch --help` documents `--quiet` and its exact one-line description, and
/// exits 0. Pins the flag's existence and help text (a help/behavior drift
/// guard), not just a non-empty help blob.
#[test]
fn watch_help_exits_zero_and_documents_quiet_flag() {
    let output = Command::new(binary())
        .args(["watch", "--help"])
        .output()
        .expect("spawn keyhog watch --help");

    assert_eq!(output.status.code(), Some(0), "watch --help must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--quiet"),
        "help must list the --quiet flag; got:\n{stdout}"
    );
    assert!(
        stdout.contains("Quiet mode: only print findings"),
        "help must carry the exact --quiet description; got:\n{stdout}"
    );
}

/// Non-quiet `watch` prints the full startup banner on STDERR: the compiled
/// header, the `Ctrl-C to exit` hint. Gated on the banner itself, which only
/// prints after the cold detector compile finishes.
#[test]
fn noisy_watch_prints_compiled_banner_on_stderr() {
    let dir = TempDir::new().expect("tempdir");
    let (mut child, _out, err) = spawn_watch(dir.path(), false);

    let ready = wait_until_contains(&err, &["detectors compiled)"], Duration::from_secs(20));
    kill(&mut child);

    assert!(
        ready,
        "noisy banner must appear on stderr; stderr=\n{}",
        snapshot(&err)
    );
    let stderr = snapshot(&err);
    assert!(
        stderr.contains("keyhog watch ("),
        "banner must name the daemon; stderr=\n{stderr}"
    );
    assert!(
        stderr.contains("Ctrl-C to exit"),
        "banner must carry the Ctrl-C hint; stderr=\n{stderr}"
    );
}

/// The banner names the canonical watched-root path after `watching:`, on
/// STDERR. Uses the OS-canonicalized tempdir so the assertion holds on hosts
/// where `/tmp` is a symlink (e.g. macOS `/private/tmp`).
#[test]
fn noisy_watch_banner_names_canonical_root_on_stderr() {
    let dir = TempDir::new().expect("tempdir");
    let canon = dir.path().canonicalize().expect("canonicalize tempdir");
    let (mut child, _out, err) = spawn_watch(dir.path(), false);

    let ready = wait_until_contains(
        &err,
        &["watching:", &canon.display().to_string()],
        Duration::from_secs(20),
    );
    kill(&mut child);

    assert!(
        ready,
        "banner must announce the canonical watched root; stderr=\n{}",
        snapshot(&err)
    );
}

/// With no changes, non-quiet `watch` keeps STDOUT clean: all startup chatter
/// is on STDERR (the banner), STDOUT carries only findings — of which there are
/// none yet. Paired positive (banner present) + STDOUT-empty check.
#[test]
fn noisy_watch_keeps_startup_chatter_off_stdout() {
    let dir = TempDir::new().expect("tempdir");
    let (mut child, out, err) = spawn_watch(dir.path(), false);

    let ready = wait_until_contains(&err, &["detectors compiled)"], Duration::from_secs(20));
    kill(&mut child);

    assert!(
        ready,
        "banner must reach stderr; stderr=\n{}",
        snapshot(&err)
    );
    assert_eq!(
        snapshot(&out).trim(),
        "",
        "no change means no finding: STDOUT must stay empty while the banner is on STDERR"
    );
}

/// Quiet `watch` still emits the finding on STDOUT with the exact detector id,
/// severity, confidence, line, and redacted value — proving `--quiet` mutes
/// only the banner, never the finding stream.
#[test]
fn quiet_watch_emits_full_finding_on_stdout() {
    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("a.env");
    let (mut child, out, _err) = spawn_watch(dir.path(), true);

    let found = plant_until_found(&file, 1, &out, Duration::from_secs(20));
    kill(&mut child);

    assert!(
        found,
        "quiet watch must still print the finding; stdout=\n{}",
        snapshot(&out)
    );
    let stdout = snapshot(&out);
    assert!(
        stdout.contains("aws-access-key"),
        "detector id missing; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Critical (1.00)"),
        "severity/confidence wrong; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains(REDACTED),
        "redacted value missing; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("a.env:1"),
        "path:line marker wrong; stdout=\n{stdout}"
    );
}

/// Quiet `watch` writes NOTHING to STDERR — not the banner, not the watched
/// root — even while findings stream to STDOUT. Negative twin of the banner
/// tests: readiness is gated on the STDOUT finding, then STDERR is asserted
/// byte-empty.
#[test]
fn quiet_watch_stderr_is_empty_even_with_findings() {
    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("a.env");
    let (mut child, out, err) = spawn_watch(dir.path(), true);

    let found = plant_until_found(&file, 1, &out, Duration::from_secs(20));
    kill(&mut child);

    assert!(
        found,
        "quiet watch must emit a finding to gate readiness; stdout=\n{}",
        snapshot(&out)
    );
    let stderr = snapshot(&err);
    assert_eq!(
        stderr, "",
        "quiet mode must produce an EMPTY stderr; got:\n{stderr}"
    );
    assert!(
        !stderr.contains("watching:"),
        "quiet stderr must omit the watching banner"
    );
    assert!(
        !stderr.contains("detectors compiled"),
        "quiet stderr must omit the compiled header"
    );
    assert!(
        !stderr.contains("Ctrl-C to exit"),
        "quiet stderr must omit the Ctrl-C hint"
    );
}

/// Quiet `watch` redacts the credential: the finding shows `AK...YA`, and the
/// full key never leaks to STDOUT. Adversarial — a redaction regression would
/// print the live secret.
#[test]
fn quiet_watch_redacts_credential_never_leaks_full_key() {
    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("leak.env");
    let (mut child, out, _err) = spawn_watch(dir.path(), true);

    let found = plant_until_found(&file, 1, &out, Duration::from_secs(20));
    kill(&mut child);

    assert!(
        found,
        "watch must fire on the planted key; stdout=\n{}",
        snapshot(&out)
    );
    let stdout = snapshot(&out);
    assert!(
        stdout.contains(REDACTED),
        "must show redacted form; stdout=\n{stdout}"
    );
    assert!(
        !stdout.contains(AWS_KEY),
        "the full credential must NEVER reach stdout; stdout=\n{stdout}"
    );
}

/// The finding travels on STDOUT, and STDERR never carries it — in quiet mode
/// STDERR is empty. Proves channel separation: findings are stdout data, not
/// diagnostics.
#[test]
fn quiet_watch_finding_is_on_stdout_not_stderr() {
    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("sep.env");
    let (mut child, out, err) = spawn_watch(dir.path(), true);

    let found = plant_until_found(&file, 1, &out, Duration::from_secs(20));
    kill(&mut child);

    assert!(found, "watch must fire; stdout=\n{}", snapshot(&out));
    assert!(
        snapshot(&out).contains("aws-access-key"),
        "finding belongs on STDOUT"
    );
    assert!(
        !snapshot(&err).contains("aws-access-key"),
        "finding must NOT appear on STDERR; stderr=\n{}",
        snapshot(&err)
    );
}

/// The STDOUT finding line is IDENTICAL under `--quiet` and non-quiet — same
/// tempdir (so the path matches), same key, same line. `--quiet` changes only
/// STDERR verbosity, never the stdout payload byte-for-byte.
#[test]
fn quiet_and_noisy_emit_identical_finding_line() {
    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("same.env");

    // Noisy run.
    let (mut noisy, noisy_out, _noisy_err) = spawn_watch(dir.path(), false);
    let n_found = plant_until_found(&file, 1, &noisy_out, Duration::from_secs(20));
    kill(&mut noisy);
    let noisy_line = line_containing(&noisy_out, "aws-access-key");

    // Quiet run on the SAME directory — re-trigger with a fresh write.
    let (mut quiet, quiet_out, _quiet_err) = spawn_watch(dir.path(), true);
    let q_found = plant_until_found(&file, 1, &quiet_out, Duration::from_secs(20));
    kill(&mut quiet);
    let quiet_line = line_containing(&quiet_out, "aws-access-key");

    assert!(
        n_found && q_found,
        "both modes must fire; noisy={n_found} quiet={q_found}"
    );
    assert_eq!(
        noisy_line, quiet_line,
        "the aws-access-key finding line must be byte-identical across quiet/noisy"
    );
    // The daemon reports the canonical event path (watch canonicalizes its
    // root), so build the expected line from the canonicalized file — this
    // holds on hosts where the tempdir root is itself a symlink.
    let canon_file = file.canonicalize().expect("canonicalize planted file");
    let expected = format!(
        "\u{1F50D} aws-access-key {}:1 Critical (1.00)  {REDACTED}",
        canon_file.display()
    );
    assert_eq!(
        quiet_line.as_deref(),
        Some(expected.as_str()),
        "finding line must match the exact expected rendering"
    );
}

/// `--quiet` shows strictly LESS on STDERR than the default. In an empty tree
/// (no findings on either), quiet STDERR is 0 bytes while noisy STDERR carries
/// the multi-line banner. Concrete byte-length ordering, not a fuzzy "similar".
#[test]
fn quiet_stderr_is_strictly_shorter_than_noisy_stderr() {
    // Noisy: gate on banner, then snapshot stderr length.
    let noisy_dir = TempDir::new().expect("tempdir");
    let (mut noisy, _noisy_out, noisy_err) = spawn_watch(noisy_dir.path(), false);
    let noisy_ready = wait_until_contains(&noisy_err, &["Ctrl-C to exit"], Duration::from_secs(20));
    kill(&mut noisy);
    let noisy_len = snapshot(&noisy_err).len();

    // Quiet: no banner to gate on; give it the same compile budget, then verify
    // it stayed silent on stderr.
    let quiet_dir = TempDir::new().expect("tempdir");
    let (mut quiet, quiet_out, quiet_err) = spawn_watch(quiet_dir.path(), true);
    // Prove the quiet daemon actually reached readiness (so an empty stderr is
    // meaningful, not just "hasn't started yet"): fire one finding.
    let qfile = quiet_dir.path().join("ready.env");
    let q_ready = plant_until_found(&qfile, 1, &quiet_out, Duration::from_secs(20));
    kill(&mut quiet);
    let quiet_len = snapshot(&quiet_err).len();

    assert!(
        noisy_ready,
        "noisy banner must appear; stderr=\n{}",
        snapshot(&noisy_err)
    );
    assert!(
        q_ready,
        "quiet daemon must reach readiness; stdout=\n{}",
        snapshot(&quiet_out)
    );
    assert_eq!(
        quiet_len, 0,
        "quiet stderr must be exactly 0 bytes; got {quiet_len}"
    );
    assert!(
        noisy_len > 0,
        "noisy stderr must be non-empty; got {noisy_len}"
    );
    assert!(
        quiet_len < noisy_len,
        "quiet must show strictly less on stderr: quiet={quiet_len} noisy={noisy_len}"
    );
}

/// An invalid `--detectors` path fails BEFORE watching with exit code 2
/// (EXIT_USER_ERROR, detector-load failure) regardless of `--quiet` — the flag
/// changes verbosity, not the exit contract. The error names the missing
/// directory on stderr in both modes.
#[test]
fn invalid_detectors_exits_two_regardless_of_quiet() {
    let dir = TempDir::new().expect("tempdir");
    let missing = dir.path().join("no-such-detectors");

    let noisy = Command::new(binary())
        .arg("watch")
        .arg(dir.path())
        .arg("--detectors")
        .arg(&missing)
        .output()
        .expect("spawn noisy");
    let quiet = Command::new(binary())
        .arg("watch")
        .arg(dir.path())
        .arg("--detectors")
        .arg(&missing)
        .arg("--quiet")
        .output()
        .expect("spawn quiet");

    assert_eq!(
        noisy.status.code(),
        Some(2),
        "noisy invalid-detectors must exit 2"
    );
    assert_eq!(
        quiet.status.code(),
        Some(2),
        "quiet invalid-detectors must exit 2"
    );
    assert_eq!(
        noisy.status.code(),
        quiet.status.code(),
        "--quiet must not change the exit code"
    );
    let noisy_err = String::from_utf8_lossy(&noisy.stderr);
    let quiet_err = String::from_utf8_lossy(&quiet.stderr);
    assert!(
        noisy_err.contains("detectors directory") && noisy_err.contains("does not exist"),
        "noisy error must name the missing detectors dir; stderr=\n{noisy_err}"
    );
    assert!(
        quiet_err.contains("detectors directory") && quiet_err.contains("does not exist"),
        "even quiet mode must surface the fatal detector-load error; stderr=\n{quiet_err}"
    );
}

/// Quiet findings report the REAL 1-based line of the credential, not a fixed
/// line 0/1: a key on line 3 renders `:3`. Boundary check on line tracking that
/// a constant would silently pass in the line-1 tests.
#[test]
fn quiet_watch_reports_real_line_number() {
    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("deep.env");
    let (mut child, out, _err) = spawn_watch(dir.path(), true);

    let found = plant_until_found(&file, 3, &out, Duration::from_secs(20));
    kill(&mut child);

    assert!(
        found,
        "watch must fire on the line-3 key; stdout=\n{}",
        snapshot(&out)
    );
    let stdout = snapshot(&out);
    assert!(
        stdout.contains("deep.env:3"),
        "finding must report the real line (3), not a constant; stdout=\n{stdout}"
    );
    assert!(
        !stdout.contains("deep.env:1"),
        "line number must not collapse to 1; stdout=\n{stdout}"
    );
}
