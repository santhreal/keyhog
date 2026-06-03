//! VECTOR 8 (ARCHITECTURE) + VECTOR 9 (WIRING) audit: the daemon scan
//! route bypasses `.keyhog.toml` policy that the in-process orchestrator
//! enforces, because the routing decision is made on the RAW CLI args
//! before the config file is ever read.
//!
//! ROOT CAUSE (single bug, three observable symptoms):
//!
//!   `crates/cli/src/subcommands/scan.rs::run` calls `daemon_route(&args)`
//!   (scan.rs:69) on the un-merged `ScanArgs`. `daemon_route` (scan.rs:97)
//!   decides whether a scan may be served by the daemon by inspecting the
//!   CLI flags only:
//!
//!       if args.lockdown || args.show_secrets || args.severity.is_some()
//!           || args.min_confidence.is_some() || args.hide_client_safe
//!       { return DaemonRoute::Forbidden; }      // scan.rs:144-157
//!
//!   The `.keyhog.toml` merge (`config::apply_config_file`, invoked via
//!   `orchestrator_config::resolve_scan_config`) runs LATER, and ONLY on
//!   the in-process path inside `ScanOrchestrator::new`
//!   (orchestrator/mod.rs:78). So when a `.keyhog.toml` sets a policy via
//!   the config file rather than a CLI flag, `daemon_route` never sees it:
//!     * `min_confidence` from `.keyhog.toml` -> `args.min_confidence` is
//!       still `None` at routing time -> the route is NOT forbidden -> the
//!       daemon's `finalize_for_report` (scan.rs:283) applies NO confidence
//!       floor at all (it has no `min_confidence` branch). Findings the
//!       operator's config says to suppress are surfaced.
//!     * `[lockdown] require = true` -> `effective_config.require_lockdown`
//!       is only checked in `ScanOrchestrator::new` (orchestrator/mod.rs:89,
//!       a fail-closed `bail!`). The daemon route never builds the
//!       orchestrator, so the fail-closed security control is silently
//!       defeated and the scan runs unprotected.
//!
//!   Net effect: scan RESULTS and a SECURITY GUARD both change purely on
//!   whether a `keyhog daemon` happens to be live (the opportunistic route
//!   in scan.rs:163 turns on merely because a socket exists). That is a
//!   coherence + wiring violation: identical inputs, divergent behavior.
//!
//! These tests are the documented failing oracles. Each runs the REAL
//! `keyhog` binary, starting an isolated daemon, and scans one planted
//! fixture once in-process (`--no-daemon`, the correct reference behavior)
//! and once over the daemon (`--daemon`), asserting PARITY. They FAIL today
//! (the daemon route diverges) and will PASS once `daemon_route` consults
//! the merged config (or `run()` merges config before routing) so a
//! config-mandated floor / lockdown-require forces the in-process path.
//!
//! Existing `regression_daemon_suppression_parity.rs` covers `.keyhogignore`
//! / inline-ignore / `.keyhogignore.toml` parity; it does NOT cover
//! `.keyhog.toml` `min_confidence` or `[lockdown] require`. These are new.
//!
//! Unix-only: the daemon and the `--daemon` flag are unix-only (the whole
//! `crate::daemon` subtree is `#[cfg(unix)]`).

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// The repo's `detectors/` directory, resolved relative to this crate's
/// manifest dir. Guarantees the real `aws-access-key` detector is loaded by
/// BOTH the daemon and the in-process path rather than whatever subset the
/// embedded corpus carries — the planted key must be detectable on both
/// routes for a parity assertion to mean anything.
fn workspace_detectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../detectors")
        .canonicalize()
        .expect("workspace detectors dir")
}

/// A planted AWS access key: `AKIA` + 16 base32 chars is the canonical AWS
/// key shape every keyhog build detects at ~0.8 confidence. Split across a
/// concat so this source file itself does not trip a self-scan. 0.8 sits
/// ABOVE the default 0.40 floor (so it is normally reported) but BELOW the
/// 0.99 floor the test's `.keyhog.toml` sets — that gap is what the floor
/// test exercises.
fn planted_secret() -> String {
    concat!("AKIA", "QYLPMN5HFIQR7XYA").to_string()
}

/// Isolated daemon with its own `XDG_RUNTIME_DIR`, so `default_socket_path()`
/// (used by both `daemon start` and `scan --daemon`) resolves to a per-test
/// socket and never collides with a real user daemon.
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

    /// Poll `daemon status` until it answers (the compiled scanner takes a
    /// beat to warm). Fails loudly on timeout so a broken daemon can never
    /// masquerade as a clean parity result.
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

/// Outcome of a single `keyhog scan` invocation.
struct ScanRun {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run `keyhog scan --format json <route_flag> <abs_path>` against the
/// daemon's isolated runtime dir. `route_flag` is `--daemon` or
/// `--no-daemon`. The path is absolute so config discovery walks up from the
/// fixture's directory regardless of CWD. We pass NO `--min-confidence` /
/// `--lockdown` CLI flag on purpose: the policy under test lives ONLY in the
/// fixture's `.keyhog.toml`, which is precisely the surface `daemon_route`
/// fails to consult.
fn scan(daemon: &Daemon, abs_path: &Path, route_flag: &str) -> ScanRun {
    let output = Command::new(binary())
        .arg("scan")
        .arg(route_flag)
        .arg("--format")
        .arg("json")
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .arg(abs_path)
        .output()
        .expect("spawn keyhog scan");
    ScanRun {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Parse a `--format json` findings array; panics with context if stdout is
/// not the expected JSON array (so a malformed run can't masquerade as
/// "empty findings").
fn findings(run: &ScanRun, label: &str) -> Vec<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(run.stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "{label}: stdout is not valid JSON ({e}); exit={:?}; stdout={:?}; stderr={:?}",
            run.exit_code, run.stdout, run.stderr
        )
    });
    value
        .as_array()
        .unwrap_or_else(|| panic!("{label}: JSON is not an array; got {value}"))
        .clone()
}

/// True when at least one finding is the planted AWS key (named detector or
/// the `hot-aws_key` fast path).
fn has_aws_finding(findings: &[serde_json::Value]) -> bool {
    findings.iter().any(|f| {
        matches!(
            f.get("detector_id").and_then(|v| v.as_str()),
            Some("aws-access-key") | Some("hot-aws_key")
        )
    })
}

fn write_fixture(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("write fixture");
    path
}

/// AUD-arch_wiring-1 — `.keyhog.toml` `min_confidence` is bypassed by the
/// daemon route.
///
/// Finding: `crates/cli/src/subcommands/scan.rs:147` forbids the daemon
/// route only when `args.min_confidence.is_some()` (the CLI flag). A floor
/// set in `.keyhog.toml` is merged into `args.min_confidence` by
/// `config::apply_config_file` (config.rs:362-364) — but that merge runs
/// inside `ScanOrchestrator::new`, AFTER `daemon_route`. The daemon's
/// `finalize_for_report` (scan.rs:283) has no confidence-floor stage at all,
/// while the in-process `filter_and_resolve` always applies the resolved
/// floor (orchestrator/postprocess.rs:161).
///
/// Reference behavior (`--no-daemon`): a 0.8-confidence finding under a
/// `.keyhog.toml` floor of 0.99 is suppressed -> empty array, exit 0.
/// Buggy behavior (`--daemon`): the finding surfaces -> non-empty array,
/// exit 1. This test asserts the two routes AGREE (parity). It FAILS today
/// because the daemon route reports the finding the config floor forbids.
///
/// Expected fix: `daemon_route` must consult the merged config (or `run()`
/// must merge config before routing) and force the in-process path whenever
/// the effective `min_confidence` floor is in play, so the floor is honored
/// regardless of whether a daemon is live.
#[test]
fn daemon_route_honors_config_min_confidence_floor() {
    let daemon = Daemon::start();
    let work = TempDir::new().expect("work tempdir");

    // Floor of 0.99 sits above the planted key's ~0.8 confidence: a
    // policy-compliant scan must drop it.
    write_fixture(work.path(), ".keyhog.toml", "min_confidence = 0.99\n");
    let secret = planted_secret();
    let path = write_fixture(
        work.path(),
        "config.txt",
        &format!("aws_key = \"{secret}\"\n"),
    );

    // Reference: in-process honors the config floor and suppresses.
    let in_process = scan(&daemon, &path, "--no-daemon");
    let in_process_findings = findings(&in_process, "in-process(--no-daemon)");
    assert!(
        !has_aws_finding(&in_process_findings),
        "control: in-process path must suppress the 0.8-confidence key under a \
         .keyhog.toml min_confidence=0.99 floor; got {in_process_findings:?}"
    );
    assert_eq!(
        in_process.exit_code,
        Some(0),
        "control: in-process suppressed scan must exit 0 (no reportable findings); \
         stderr={}",
        in_process.stderr
    );

    // Under test: the daemon route MUST reach the same suppressed result.
    let via_daemon = scan(&daemon, &path, "--daemon");
    let daemon_findings = findings(&via_daemon, "daemon(--daemon)");
    assert!(
        !has_aws_finding(&daemon_findings),
        "BUG: daemon route ignored the .keyhog.toml min_confidence=0.99 floor and \
         surfaced a 0.8-confidence finding the in-process path suppressed \
         (results change purely because a daemon is running). daemon={daemon_findings:?}"
    );
    assert_eq!(
        via_daemon.exit_code, in_process.exit_code,
        "daemon route exit code must match in-process under a config min_confidence \
         floor; daemon stdout={:?} stderr={:?}",
        via_daemon.stdout, via_daemon.stderr
    );
}

/// AUD-arch_wiring-2 — `[lockdown] require = true` (a fail-closed security
/// control) is bypassed by the daemon route.
///
/// Finding: `ScanOrchestrator::new` enforces `[lockdown] require = true`
/// with a `bail!` (orchestrator/mod.rs:89-95) when `--lockdown` was not
/// passed — a deliberate fail-closed guard so a repo that mandates hardening
/// never runs unprotected. But that check lives inside the orchestrator,
/// which the daemon route never constructs. `daemon_route` (scan.rs:97) only
/// looks at the `args.lockdown` CLI flag, not the config-file
/// `require_lockdown` (which isn't even parsed until after routing). So a
/// daemon-routed scan silently DEFEATS the lockdown-required guard.
///
/// Reference behavior (`--no-daemon`): exit code 2 with the lockdown error
/// on stderr; no findings emitted (fail closed).
/// Buggy behavior (`--daemon`): the scan runs normally — exit 1 with the
/// finding on stdout. This test asserts the daemon route ALSO fails closed.
/// It FAILS today because the daemon route scans instead of refusing.
///
/// Expected fix: route the scan in-process (or otherwise enforce the
/// requirement) whenever `.keyhog.toml` sets `[lockdown] require = true`, so
/// the fail-closed control holds regardless of daemon presence.
#[test]
fn daemon_route_enforces_config_lockdown_require() {
    let daemon = Daemon::start();
    let work = TempDir::new().expect("work tempdir");

    write_fixture(
        work.path(),
        ".keyhog.toml",
        "[lockdown]\nrequire = true\n",
    );
    let secret = planted_secret();
    let path = write_fixture(
        work.path(),
        "config.txt",
        &format!("aws_key = \"{secret}\"\n"),
    );

    // Reference: in-process fails closed (exit 2, lockdown error, no scan).
    let in_process = scan(&daemon, &path, "--no-daemon");
    assert_eq!(
        in_process.exit_code,
        Some(2),
        "control: in-process must fail closed (exit 2) under \
         [lockdown] require = true without --lockdown; stdout={:?} stderr={:?}",
        in_process.stdout,
        in_process.stderr
    );
    assert!(
        in_process.stderr.contains("[lockdown] require = true"),
        "control: in-process must emit the lockdown-required error; stderr={:?}",
        in_process.stderr
    );

    // Under test: the daemon route must ALSO refuse to scan. Today it runs
    // the scan and exits 1 with the finding — the security control is gone.
    let via_daemon = scan(&daemon, &path, "--daemon");
    assert_ne!(
        via_daemon.exit_code,
        Some(1),
        "BUG: daemon route ignored [lockdown] require = true and ran the scan \
         (exit 1 with findings), defeating a fail-closed security control the \
         in-process path enforces. stdout={:?} stderr={:?}",
        via_daemon.stdout,
        via_daemon.stderr
    );
    assert_eq!(
        via_daemon.exit_code,
        Some(2),
        "daemon route must fail closed (exit 2) under [lockdown] require = true, \
         matching the in-process path; stdout={:?} stderr={:?}",
        via_daemon.stdout,
        via_daemon.stderr
    );
}

/// AUD-arch_wiring-3 — `show_secrets = true` from `.keyhog.toml` produces
/// different OUTPUT over the daemon route than in-process.
///
/// Finding: same root cause. `config::apply_config_file` merges
/// `.keyhog.toml` `show_secrets` into `args.show_secrets`, but only inside
/// the orchestrator. `daemon_route` (scan.rs:145) forbids the daemon path
/// only when the `args.show_secrets` CLI flag is set; the config-file value
/// is invisible at routing time. The in-process path then prints the full
/// credential, while the daemon's `finalize_for_report` (scan.rs:375)
/// redacts it — the operator's documented config silently changes the output
/// based on whether a daemon is live.
///
/// This test asserts the redacted/plaintext rendering is the SAME on both
/// routes. It FAILS today (in-process shows the full key; daemon redacts).
///
/// Expected fix: as above — config-driven `show_secrets` must force the
/// in-process path (or the daemon route must honor it), so credential
/// rendering does not depend on daemon presence.
#[test]
fn daemon_route_honors_config_show_secrets() {
    let daemon = Daemon::start();
    let work = TempDir::new().expect("work tempdir");

    write_fixture(work.path(), ".keyhog.toml", "show_secrets = true\n");
    let secret = planted_secret();
    let path = write_fixture(
        work.path(),
        "config.txt",
        &format!("aws_key = \"{secret}\"\n"),
    );

    let rendered = |run: &ScanRun, label: &str| -> String {
        let fs = findings(run, label);
        let aws = fs
            .iter()
            .find(|f| {
                matches!(
                    f.get("detector_id").and_then(|v| v.as_str()),
                    Some("aws-access-key") | Some("hot-aws_key")
                )
            })
            .unwrap_or_else(|| panic!("{label}: expected an AWS finding; got {fs:?}"));
        aws.get("credential_redacted")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{label}: finding has no credential_redacted field"))
            .to_string()
    };

    // Reference: in-process honors show_secrets and prints the full key.
    let in_process = scan(&daemon, &path, "--no-daemon");
    let in_process_cred = rendered(&in_process, "in-process(--no-daemon)");
    assert_eq!(
        in_process_cred, secret,
        "control: in-process must print the full credential under \
         .keyhog.toml show_secrets=true; got {in_process_cred:?}"
    );

    // Under test: the daemon route must render the credential identically.
    let via_daemon = scan(&daemon, &path, "--daemon");
    let daemon_cred = rendered(&via_daemon, "daemon(--daemon)");
    assert_eq!(
        daemon_cred, in_process_cred,
        "BUG: daemon route ignored .keyhog.toml show_secrets=true and redacted the \
         credential while the in-process path printed it in full \
         (output changes purely because a daemon is running). \
         daemon={daemon_cred:?} in_process={in_process_cred:?}"
    );
}
