//! VECTOR 8 (ARCHITECTURE) + VECTOR 9 (WIRING) audit: daemon routing must
//! honor `.keyhog.toml` policy before it decides whether a scan can be served
//! by the long-lived daemon.
//!
//! The daemon can only serve a narrow scanner-match route. Config-driven
//! confidence floors, lockdown requirements, secret-output policy, allowlist
//! governance, and similar per-request policy must either stay in-process or
//! fail closed when the operator forced `--daemon=on`. These tests start an
//! isolated daemon and prove forced daemon scans reject policy the daemon cannot
//! enforce instead of silently changing results.
//!
//! Existing `regression_daemon_suppression_parity.rs` covers `.keyhogignore`
//! / inline-ignore / `.keyhogignore.toml` parity; it does NOT cover
//! `.keyhog.toml` `min_confidence` or `[lockdown] require`. These are new.
//!
//! Unix-only: the daemon and the `--daemon` flag are unix-only (the whole
//! `crate::daemon` subtree is `#[cfg(unix)]`).
//!
//! Requires the `simd` feature: the daemon is started with `--cache-dir`
//! (Hyperscan DB cache) and `--backend simd`, both of which a non-simd build
//! rejects ("--cache-dir requires a keyhog build with the simd feature"), so the
//! spawned daemon exits before becoming ready. Gating on `feature = "simd"` makes
//! a bare `cargo test -p keyhog` (default features) skip these cleanly instead of
//! failing with a confusing "daemon exited before becoming ready; status=2"; CI
//! runs them under `--features simd`.

#![cfg(all(unix, feature = "simd"))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// The repo's `detectors/` directory, resolved relative to this crate's
/// manifest dir. Guarantees the real `aws-access-key` detector is loaded by
/// BOTH the daemon and the in-process path rather than whatever subset the
/// embedded corpus carries, the planted key must be detectable on both
/// routes for a parity assertion to mean anything.
fn workspace_detectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../detectors")
        .canonicalize()
        .expect("workspace detectors dir")
}

fn daemon_slot() -> MutexGuard<'static, ()> {
    static DAEMON_SLOT: OnceLock<Mutex<()>> = OnceLock::new();
    DAEMON_SLOT
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn test_cache_root() -> &'static TempDir {
    static CACHE_ROOT: OnceLock<TempDir> = OnceLock::new();
    CACHE_ROOT.get_or_init(|| {
        let uid = unsafe { libc::geteuid() };
        let allowed_root = std::env::temp_dir().join(format!("keyhog-cache-{uid}"));
        std::fs::create_dir_all(&allowed_root).expect("allowed daemon cache root");
        std::fs::set_permissions(&allowed_root, std::fs::Permissions::from_mode(0o700))
            .expect("private allowed daemon cache root");
        let dir = tempfile::Builder::new()
            .prefix("audit-arch-wiring-")
            .tempdir_in(&allowed_root)
            .expect("daemon cache root");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private daemon cache root");
        std::fs::create_dir_all(dir.path().join("xdg")).expect("daemon xdg cache dir");
        std::fs::create_dir_all(dir.path().join("hyperscan")).expect("daemon hyperscan cache dir");
        dir
    })
}

fn test_xdg_cache_home() -> PathBuf {
    test_cache_root().path().join("xdg")
}

fn test_hyperscan_cache_dir() -> PathBuf {
    test_cache_root().path().join("hyperscan")
}

/// A planted AWS access key used by lockdown/show-secrets tests. Split across
/// a concat so this source file itself does not trip a self-scan.
fn planted_secret() -> String {
    concat!("AKIA", "QYLPMN5HFIQR7XYA").to_string()
}

/// A generic key/value secret that reports below a 0.99 confidence floor.
const LOW_CONFIDENCE_SECRET: &str = "aAbBcCdDeEfFgGhH12345678";

/// Isolated daemon with its own `XDG_RUNTIME_DIR`, so `default_socket_path()`
/// (used by both `daemon start` and `scan --daemon`) resolves to a per-test
/// socket and never collides with a real user daemon.
struct Daemon {
    _slot: MutexGuard<'static, ()>,
    child: Child,
    runtime_dir: TempDir,
    xdg_cache_home: PathBuf,
    hyperscan_cache_dir: PathBuf,
    socket: PathBuf,
}

impl Daemon {
    fn start() -> Daemon {
        let slot = daemon_slot();
        let runtime_dir = TempDir::new().expect("runtime tempdir");
        std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private runtime tempdir");
        let xdg_cache_home = test_xdg_cache_home();
        let hyperscan_cache_dir = test_hyperscan_cache_dir();
        let socket = runtime_dir.path().join("keyhog.sock");

        let child = Command::new(binary())
            .arg("daemon")
            .arg("start")
            .env("XDG_RUNTIME_DIR", runtime_dir.path())
            .env("XDG_CACHE_HOME", &xdg_cache_home)
            .arg("--detectors")
            .arg(workspace_detectors())
            .arg("--cache-dir")
            .arg(&hyperscan_cache_dir)
            .arg("--backend")
            .arg("simd")
            .spawn()
            .expect("spawn keyhog daemon start");

        let mut daemon = Daemon {
            _slot: slot,
            child,
            runtime_dir,
            xdg_cache_home,
            hyperscan_cache_dir,
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
    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll daemon startup") {
                panic!(
                    "daemon exited before becoming ready; status={:?}",
                    status.code()
                );
            }
            let status = Command::new(binary())
                .arg("daemon")
                .arg("status")
                .env("XDG_RUNTIME_DIR", self.runtime_dir.path())
                .env("XDG_CACHE_HOME", &self.xdg_cache_home)
                .arg("--socket")
                .arg(&self.socket)
                .output()
                .expect("spawn keyhog daemon status");
            if status.status.success() {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "daemon never became ready within 180s; status stderr={}",
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
            .env("XDG_CACHE_HOME", &self.xdg_cache_home)
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
/// `--daemon=off`. The path is absolute so config discovery walks up from the
/// fixture's directory regardless of CWD. We pass NO `--min-confidence` /
/// `--lockdown` CLI flag on purpose: the policy under test lives ONLY in the
/// fixture's `.keyhog.toml`, which is precisely the surface `daemon_route`
/// fails to consult.
fn scan(daemon: &Daemon, abs_path: &Path, route_flag: &str) -> ScanRun {
    let mut command = Command::new(binary());
    command
        .arg("scan")
        .arg(route_flag)
        .arg("--format")
        .arg("json")
        .arg("--backend")
        .arg("simd")
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .env("XDG_CACHE_HOME", &daemon.xdg_cache_home);
    if route_flag == "--daemon=off" {
        command.arg("--cache-dir").arg(&daemon.hyperscan_cache_dir);
    }
    let output = command.arg(abs_path).output().expect("spawn keyhog scan");
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

fn write_fixture(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("write fixture");
    path
}

/// AUD-arch_wiring-1: `.keyhog.toml` `min_confidence` must be considered
/// before a forced daemon route is accepted.
#[test]
fn daemon_route_honors_config_min_confidence_floor() {
    let daemon = Daemon::start();
    let work = TempDir::new().expect("work tempdir");

    write_fixture(
        work.path(),
        ".keyhog.toml",
        "[scan]\nmin_confidence = 0.99\n",
    );
    let path = write_fixture(
        work.path(),
        "config.txt",
        &format!("api_key = \"{LOW_CONFIDENCE_SECRET}\"\n"),
    );

    // Reference: in-process honors the config floor and suppresses.
    let in_process = scan(&daemon, &path, "--daemon=off");
    let in_process_findings = findings(&in_process, "in-process(--daemon=off)");
    assert!(
        in_process_findings.is_empty(),
        "control: in-process path must suppress the sub-0.99 generic secret under a \
         .keyhog.toml min_confidence=0.99 floor; got {in_process_findings:?}"
    );
    assert_eq!(
        in_process.exit_code,
        Some(0),
        "control: in-process suppressed scan must exit 0 (no reportable findings); \
         stderr={}",
        in_process.stderr
    );

    // Under test: forced daemon must fail closed because it cannot enforce the
    // confidence floor itself.
    let via_daemon = scan(&daemon, &path, "--daemon");
    assert_eq!(
        via_daemon.exit_code,
        Some(2),
        "forced daemon route must fail closed under config min_confidence policy; stdout={:?} stderr={:?}",
        via_daemon.stdout, via_daemon.stderr
    );
    assert!(
        via_daemon.stderr.contains("--daemon=on cannot be honored")
            && via_daemon.stderr.contains("config policy"),
        "forced daemon rejection must explain that config policy cannot be honored; stderr={:?}",
        via_daemon.stderr
    );
}

/// AUD-arch_wiring-2: `[lockdown] require = true` (a fail-closed security
/// control) is bypassed by the daemon route.
///
/// Finding: `ScanOrchestrator::new` enforces `[lockdown] require = true`
/// with a `bail!` (orchestrator/mod.rs:89-95) when `--lockdown` was not
/// passed, a deliberate fail-closed guard so a repo that mandates hardening
/// never runs unprotected. But that check lives inside the orchestrator,
/// which the daemon route never constructs. `daemon_route` (scan.rs:97) only
/// looks at the `args.lockdown` CLI flag, not the config-file
/// `require_lockdown` (which isn't even parsed until after routing). So a
/// daemon-routed scan silently DEFEATS the lockdown-required guard.
///
/// Reference behavior (`--daemon=off`): exit code 2 with the lockdown error
/// on stderr; no findings emitted (fail closed).
/// Buggy behavior (`--daemon`): the scan runs normally, exit 1 with the
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

    write_fixture(work.path(), ".keyhog.toml", "[lockdown]\nrequire = true\n");
    let secret = planted_secret();
    let path = write_fixture(
        work.path(),
        "config.txt",
        &format!("aws_key = \"{secret}\"\n"),
    );

    // Reference: in-process fails closed (exit 2, lockdown error, no scan).
    let in_process = scan(&daemon, &path, "--daemon=off");
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
    // the scan and exits 1 with the finding (the security control is gone).
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

/// AUD-arch_wiring-3: `show_secrets = true` from `.keyhog.toml` must not be
/// served by a forced daemon route that would redact differently.
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
    let in_process = scan(&daemon, &path, "--daemon=off");
    let in_process_cred = rendered(&in_process, "in-process(--daemon=off)");
    assert_eq!(
        in_process_cred, secret,
        "control: in-process must print the full credential under \
         .keyhog.toml show_secrets=true; got {in_process_cred:?}"
    );

    // Under test: forced daemon must reject the route instead of rendering a
    // different redacted value.
    let via_daemon = scan(&daemon, &path, "--daemon");
    assert_eq!(
        via_daemon.exit_code,
        Some(2),
        "forced daemon route must fail closed under config show_secrets policy; stdout={:?} stderr={:?}",
        via_daemon.stdout, via_daemon.stderr
    );
    assert!(
        via_daemon.stderr.contains("--daemon=on cannot be honored")
            && via_daemon.stderr.contains("secret-output"),
        "forced daemon rejection must explain that secret-output policy cannot be honored; stderr={:?}",
        via_daemon.stderr
    );
}
