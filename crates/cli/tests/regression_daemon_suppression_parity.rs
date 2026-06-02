//! Regression: the daemon scan fast path must honour the same
//! suppression layers as the in-process orchestrator.
//!
//! Finding under test: `crates/cli/src/subcommands/scan.rs`
//! `finalize_for_report` (the CLI-side post-processing for a
//! daemon-routed scan) originally applied ONLY test-fixture suppression
//! and dedup. It ignored:
//!
//!   1. inline `keyhog:ignore` / `gitleaks:allow` comment directives,
//!   2. the legacy line-based `.keyhogignore` allowlist
//!      (`detector:` / `path:` / `hash:` entries),
//!   3. the declarative `.keyhogignore.toml` rule suppressor.
//!
//! The in-process path (`orchestrator::run` + `filter_and_resolve`)
//! applies all three. So a finding a user explicitly suppressed would
//! reappear the instant a `keyhog daemon` happened to be running and the
//! opportunistic route kicked in - results changing purely on daemon
//! presence. These tests drive the real `keyhog` binary: they start an
//! isolated daemon, scan a planted-secret fixture once over the daemon
//! (`--daemon`) and once in-process (`--no-daemon`), and assert the two
//! produce the SAME findings under each suppression mechanism.
//!
//! Each test is unix-only because the daemon (and the `--daemon` flag)
//! is unix-only - on other platforms the whole route short-circuits.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// The repo's `detectors/` directory, resolved relative to this crate's
/// manifest dir (same anchor the other daemon e2e tests use). Guarantees
/// the real `aws-access-key` detector is loaded by the daemon rather than
/// relying on whatever subset the embedded corpus carries.
fn workspace_detectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../detectors")
        .canonicalize()
        .expect("workspace detectors dir")
}

/// A planted AWS access key. The `AKIA` prefix + 16 base32 chars is the
/// canonical AWS key shape every keyhog build detects (named
/// `aws-access-key` detector or the `hot-aws_key` simd fast path). Split
/// across a concat so this source file itself does not trip a self-scan.
fn planted_secret() -> String {
    concat!("AKIA", "QYLPMN5HFIQR7XYA").to_string()
}

/// Isolated daemon: its own `XDG_RUNTIME_DIR` so `default_socket_path()`
/// (used by BOTH `daemon start` and `scan --daemon`) resolves to a
/// per-test socket and never collides with a real user daemon.
struct Daemon {
    child: Child,
    runtime_dir: TempDir,
    socket: PathBuf,
}

impl Daemon {
    fn start() -> Daemon {
        let runtime_dir = TempDir::new().expect("runtime tempdir");
        let socket = runtime_dir.path().join("keyhog.sock");

        let child = Command::new(binary())
            .arg("daemon")
            .arg("start")
            .env("XDG_RUNTIME_DIR", runtime_dir.path())
            .arg("--detectors")
            .arg(workspace_detectors())
            .spawn()
            .expect("spawn keyhog daemon start");

        let daemon = Daemon {
            child,
            runtime_dir,
            socket,
        };
        daemon.wait_until_ready();
        daemon
    }

    fn runtime_dir(&self) -> &Path {
        self.runtime_dir.path()
    }

    /// Poll `daemon status` against this daemon's socket until it answers
    /// (the compiled scanner takes a beat to warm). Fails the test loudly
    /// if it never comes up - a silent timeout would let a broken daemon
    /// masquerade as "no findings to suppress".
    fn wait_until_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let status = Command::new(binary())
                .arg("daemon")
                .arg("status")
                .env("XDG_RUNTIME_DIR", self.runtime_dir.path())
                .arg("--socket")
                .arg(&self.socket)
                .output()
                .expect("spawn keyhog daemon status");
            if status.status.success() {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "daemon never became ready within 60s; status stderr={}",
                    String::from_utf8_lossy(&status.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Best-effort graceful stop, then hard kill so a hung daemon
        // never leaks past the test process.
        let _ = Command::new(binary())
            .arg("daemon")
            .arg("stop")
            .env("XDG_RUNTIME_DIR", self.runtime_dir.path())
            .arg("--socket")
            .arg(&self.socket)
            .output();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Run `keyhog scan --format json <route_flag> <path>` against the given
/// daemon's runtime dir. `route_flag` is `--daemon` or `--no-daemon`.
/// Returns the parsed JSON findings array.
fn scan_json(daemon: &Daemon, path: &Path, route_flag: &str) -> Vec<serde_json::Value> {
    let output = Command::new(binary())
        .arg("scan")
        .arg(route_flag)
        .arg("--format")
        .arg("json")
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        // Keep the scan focused on the planted file; no ML/network knobs
        // that would force the route back in-process (see `daemon_route`).
        .arg(path)
        .output()
        .expect("spawn keyhog scan");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "scan {route_flag} stdout is not valid JSON ({e}); stdout={stdout}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    value
        .as_array()
        .unwrap_or_else(|| panic!("scan {route_flag} JSON is not an array; got {value}"))
        .clone()
}

/// Detector IDs present in a findings array.
fn detector_ids(findings: &[serde_json::Value]) -> Vec<String> {
    findings
        .iter()
        .filter_map(|f| f.get("detector_id").and_then(|v| v.as_str()))
        .map(str::to_owned)
        .collect()
}

/// True when at least one finding looks like the planted AWS key
/// (`aws-access-key` named detector or the `hot-aws_key` fast path).
fn has_aws_finding(findings: &[serde_json::Value]) -> bool {
    detector_ids(findings)
        .iter()
        .any(|id| id == "aws-access-key" || id == "hot-aws_key")
}

/// Write `content` to `dir/filename` and return the absolute path.
fn write_fixture(dir: &Path, filename: &str, content: &str) -> PathBuf {
    let path = dir.join(filename);
    std::fs::write(&path, content).expect("write fixture");
    path
}

/// Baseline: with no suppression in play at all, BOTH routes must surface
/// the planted AWS key. This proves the secret is detectable over the
/// daemon in the first place, so a later "daemon found nothing" is real
/// suppression parity and not a dead detector.
#[test]
fn daemon_and_in_process_both_detect_unsuppressed_secret() {
    let daemon = Daemon::start();
    let work = TempDir::new().expect("work tempdir");
    let secret = planted_secret();
    let path = write_fixture(
        work.path(),
        "config.txt",
        &format!("aws_key = \"{secret}\"\n"),
    );

    let daemon_findings = scan_json(&daemon, &path, "--daemon");
    let in_process_findings = scan_json(&daemon, &path, "--no-daemon");

    assert!(
        has_aws_finding(&daemon_findings),
        "daemon route must detect the planted AWS key; got {daemon_findings:?}"
    );
    assert!(
        has_aws_finding(&in_process_findings),
        "in-process route must detect the planted AWS key; got {in_process_findings:?}"
    );
}

/// Inline `keyhog:ignore` on the secret's own line. The in-process path
/// drops it (`filter_inline_suppressions`); the daemon path must too.
/// Before the fix, the daemon route ignored the directive and reported
/// the key, diverging from `--no-daemon`.
#[test]
fn daemon_honors_inline_keyhog_ignore() {
    let daemon = Daemon::start();
    let work = TempDir::new().expect("work tempdir");
    let secret = planted_secret();
    // `# keyhog:ignore` trailing comment: `#` is a recognised comment
    // marker and the directive sits at the start of the comment body, so
    // `inline_suppression` suppresses every finding on this line.
    let path = write_fixture(
        work.path(),
        "config.txt",
        &format!("aws_key = \"{secret}\"  # keyhog:ignore\n"),
    );

    let in_process_findings = scan_json(&daemon, &path, "--no-daemon");
    assert!(
        !has_aws_finding(&in_process_findings),
        "control: in-process path must suppress the inline-ignored key; got {in_process_findings:?}"
    );

    let daemon_findings = scan_json(&daemon, &path, "--daemon");
    assert!(
        !has_aws_finding(&daemon_findings),
        "daemon route must honour inline keyhog:ignore (parity with --no-daemon); got {daemon_findings:?}"
    );
    // Parity is exact: both routes drop the only secret, leaving an empty
    // findings array.
    assert!(
        daemon_findings.is_empty() && in_process_findings.is_empty(),
        "both routes must end with zero findings; daemon={daemon_findings:?} in_process={in_process_findings:?}"
    );
}

/// `.keyhogignore` `detector:<id>` entry. The allowlist root is the
/// scanned file's directory, so the `.keyhogignore` lives next to the
/// fixture. The in-process path drops the finding; the daemon path must
/// match.
#[test]
fn daemon_honors_keyhogignore_detector_entry() {
    let daemon = Daemon::start();
    let work = TempDir::new().expect("work tempdir");
    let secret = planted_secret();
    let path = write_fixture(
        work.path(),
        "config.txt",
        &format!("aws_key = \"{secret}\"\n"),
    );

    // Discover the exact detector id the running build assigns to this
    // key (named detector vs hot-pattern), then suppress precisely that
    // id - asserting truth, not a guessed constant.
    let baseline = scan_json(&daemon, &path, "--no-daemon");
    assert!(
        has_aws_finding(&baseline),
        "baseline must detect the key before we suppress it; got {baseline:?}"
    );
    let aws_id = detector_ids(&baseline)
        .into_iter()
        .find(|id| id == "aws-access-key" || id == "hot-aws_key")
        .expect("an AWS detector id in the baseline findings");

    write_fixture(
        work.path(),
        ".keyhogignore",
        &format!("detector:{aws_id}\n"),
    );

    let in_process_findings = scan_json(&daemon, &path, "--no-daemon");
    assert!(
        !has_aws_finding(&in_process_findings),
        "control: in-process path must drop the allowlisted detector; got {in_process_findings:?}"
    );

    let daemon_findings = scan_json(&daemon, &path, "--daemon");
    assert!(
        !has_aws_finding(&daemon_findings),
        "daemon route must honour .keyhogignore detector: entry (parity with --no-daemon); got {daemon_findings:?}"
    );
}

/// `.keyhogignore.toml` declarative `[[suppress]]` rule keyed on the
/// detector id. The in-process path applies this after dedup; the daemon
/// path must apply the identical rule.
#[test]
fn daemon_honors_keyhogignore_toml_rule() {
    let daemon = Daemon::start();
    let work = TempDir::new().expect("work tempdir");
    let secret = planted_secret();
    let path = write_fixture(
        work.path(),
        "config.txt",
        &format!("aws_key = \"{secret}\"\n"),
    );

    let baseline = scan_json(&daemon, &path, "--no-daemon");
    assert!(
        has_aws_finding(&baseline),
        "baseline must detect the key before we suppress it; got {baseline:?}"
    );
    let aws_id = detector_ids(&baseline)
        .into_iter()
        .find(|id| id == "aws-access-key" || id == "hot-aws_key")
        .expect("an AWS detector id in the baseline findings");

    write_fixture(
        work.path(),
        ".keyhogignore.toml",
        &format!("[[suppress]]\ndetector = \"{aws_id}\"\n"),
    );

    let in_process_findings = scan_json(&daemon, &path, "--no-daemon");
    assert!(
        !has_aws_finding(&in_process_findings),
        "control: in-process path must drop the rule-suppressed detector; got {in_process_findings:?}"
    );

    let daemon_findings = scan_json(&daemon, &path, "--daemon");
    assert!(
        !has_aws_finding(&daemon_findings),
        "daemon route must honour .keyhogignore.toml [[suppress]] (parity with --no-daemon); got {daemon_findings:?}"
    );
}
