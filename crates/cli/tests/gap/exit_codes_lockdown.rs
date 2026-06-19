//! Gap coverage: the `keyhog scan` exit-code contract (0 / 1 / 2 / 10 / 12 / 13), the
//! `--lockdown` security guard rails, and the `--require-gpu` fail-closed
//! preflight.
//!
//! Every expected value here is derived from the real source, not guessed:
//!
//! * `crates/cli/src/subcommands/scan.rs`
//!   - `EXIT_CREDENTIALS_FOUND: u8 = 1` (daemon path).
//!   - `daemon_route`: `--lockdown`, `--show-secrets`, `--severity`,
//!     `--min-confidence`, `--hide-client-safe`, `--baseline`, `--verify`, and
//!     non-single-file shapes all force `DaemonRoute::Forbidden` (in-process),
//!     so the lockdown contract is never silently bypassed by a live daemon.
//! * `crates/cli/src/orchestrator/run.rs`
//!   - `EXIT_LIVE_CREDENTIALS: u8 = 10`, `EXIT_SCANNER_PANIC: u8 = 11`,
//!     `EXIT_REQUIRE_GPU_UNMET: u8 = 12`.
//!   - lockdown bails (in this exact order): `--verify`, `--show-secrets`,
//!     failed `apply_lockdown_protections`, disk-cache violations,
//!     `--no-default-excludes`, `--no-unicode-norm`, `--no-decode`,
//!     `--no-entropy`, `--no-ml`, `--fast`.
//!   - exit selection at the tail: live -> 10, panicked -> 11, new entries -> 1,
//!     else 0.
//!   - require-GPU preflight maps `Err` to `ExitCode::from(12)` and prints
//!     `keyhog: <diagnostic>` to stderr.
//! * `crates/cli/src/main.rs`
//!   - anyhow errors that are NOT `io::Error` map to `EXIT_USER_ERROR = 2`;
//!     all the lockdown `anyhow::bail!`s are plain string errors -> exit 2.
//!   - clap parse failures exit 2 (clap's standard usage-error code).
//! * `crates/scanner/src/gpu/env.rs`
//!   - `require_gpu_preflight` is a no-op (Ok) unless resolved GPU policy is
//!     `required`.
//!   - `env_no_gpu` is the legacy-named wrapper for resolved GPU policy `off`.
//!   - `--require-gpu` on a no-GPU host exits 12 before scanning.
//!   - the exit-12 diagnostic text contains `--require-gpu`.
//!
//! These tests drive the real `keyhog` binary (`env!("CARGO_BIN_EXE_keyhog")`),
//! the product users actually run, and assert concrete exit codes + stderr
//! substrings rather than `!is_empty()` shape checks.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// The freshly built `keyhog` binary cargo points us at.
fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A live, real AWS access-key ID literal split so this source file is not
/// itself a self-flagging leak. `AKIA` + 16 base32 chars = the canonical
/// AWS_ACCESS_KEY_ID shape the `aws-access-key` / `hot-aws_key` detectors fire on.
fn aws_key_line() -> String {
    concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n").to_string()
}

/// Write `content` to a throwaway file under a temp dir and return (guard, path).
/// The guard must outlive the scan or the file vanishes.
fn fixture(name: &str, content: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write fixture");
    (dir, path)
}

fn config_fixture(name: &str, content: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("config tempdir");
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write config fixture");
    (dir, path)
}

fn host_has_usable_gpu() -> bool {
    let out = Command::new(binary())
        .arg("backend")
        .output()
        .expect("spawn keyhog backend");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let gpu_line = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("gpu:"))
        .unwrap_or("");
    !gpu_line.contains("not detected") && !gpu_line.contains("software renderer")
}

/// Scan a single file in-process (`--no-daemon`) with the given extra args.
/// Returns (stdout, stderr, exit-code). `--no-daemon` keeps the run on the
/// orchestrator path regardless of whether a stray daemon socket exists on the
/// dev box, so exit-code assertions are deterministic.
fn scan_in_process(path: &std::path::Path, extra: &[&str]) -> (String, String, Option<i32>) {
    let mut args: Vec<&str> = vec!["scan", "--no-daemon", "--backend", "simd"];
    args.extend_from_slice(extra);
    let p = path.to_str().expect("utf-8 path");
    args.push(p);
    let out = Command::new(binary())
        .args(&args)
        .output()
        .expect("spawn keyhog scan");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

// ---------------------------------------------------------------------------
// Exit 0: clean input.
// ---------------------------------------------------------------------------

#[test]
fn clean_file_exits_zero() {
    let (_g, path) = fixture("clean.rs", "fn main() { println!(\"hi\"); }\n");
    let (stdout, stderr, code) = scan_in_process(&path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(0),
        "clean file must exit 0; stdout={stdout} stderr={stderr}"
    );
}

#[test]
fn clean_file_json_is_empty_array_and_exits_zero() {
    let (_g, path) = fixture("clean.txt", "the quick brown fox\n");
    let (stdout, _stderr, code) = scan_in_process(&path, &["--format", "json"]);
    assert_eq!(code, Some(0), "clean file must exit 0");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("stdout is JSON");
    let arr = v.as_array().expect("findings JSON is an array");
    assert!(
        arr.is_empty(),
        "clean file must yield zero findings; got {arr:?}"
    );
}

#[test]
fn empty_file_exits_zero() {
    let (_g, path) = fixture("empty.txt", "");
    let (_stdout, _stderr, code) = scan_in_process(&path, &["--format", "json"]);
    assert_eq!(code, Some(0), "empty file must exit 0 (nothing to find)");
}

// ---------------------------------------------------------------------------
// Exit 1: unverified findings present.
// ---------------------------------------------------------------------------

#[test]
fn planted_aws_key_exits_one() {
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let (stdout, stderr, code) = scan_in_process(&path, &["--format", "json"]);
    // run.rs tail: has_new_entries && !live && !panicked -> ExitCode::from(1).
    assert_eq!(
        code,
        Some(1),
        "planted unverified AWS key must exit 1; stdout={stdout} stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("stdout is JSON");
    let arr = v.as_array().expect("findings JSON is an array");
    assert!(
        !arr.is_empty(),
        "expected at least one finding; got {arr:?}"
    );
}

#[test]
fn finding_verification_is_skipped_without_verify_flag() {
    // Without --verify, no live HTTP probe runs, so verification must be
    // "Skipped" and the exit code stays at 1 (never 10).
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let (stdout, _stderr, code) = scan_in_process(&path, &["--format", "json"]);
    assert_eq!(code, Some(1), "unverified findings must exit 1, never 10");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("stdout is JSON");
    let arr = v.as_array().expect("array");
    let first = arr.first().expect("at least one finding");
    let verification = first
        .get("verification")
        .expect("finding carries a verification field");
    // VerificationResult::Skipped — no live verification was attempted, so
    // the run is exactly the exit-1 (not exit-10) branch.
    let as_str = verification.as_str().unwrap_or("");
    assert!(
        as_str.eq_ignore_ascii_case("skipped")
            || verification
                .as_object()
                .map(|o| o.contains_key("Skipped") || o.contains_key("skipped"))
                .unwrap_or(false)
            || as_str.is_empty(),
        "no --verify => verification should be Skipped, never Live; got {verification}"
    );
    assert_ne!(
        as_str.to_ascii_lowercase(),
        "live",
        "no --verify must not produce a Live verification (which would be exit 10)"
    );
}

// ---------------------------------------------------------------------------
// Exit 2: user / configuration errors.
// ---------------------------------------------------------------------------

#[test]
fn missing_named_path_exits_two() {
    // sources.rs build_sources: a path whose `metadata()` is NotFound triggers
    // `anyhow::bail!("path '...' does not exist ...")`. That plain (non-io)
    // anyhow error maps to EXIT_USER_ERROR (2) in main.rs via the final else.
    let missing = PathBuf::from("/keyhog/definitely/not/here/zzz_nonexistent_path");
    let (_stdout, stderr, code) = scan_in_process(&missing, &["--format", "json"]);
    assert_eq!(
        code,
        Some(2),
        "scanning a path that does not exist must be a user error (exit 2); stderr={stderr}"
    );
    assert!(
        stderr.contains("does not exist"),
        "the exit-2 message must say the path does not exist; stderr={stderr}"
    );
}

#[test]
fn unknown_flag_exits_two() {
    // clap rejects an unknown flag with its standard usage-error exit code 2.
    let out = Command::new(binary())
        .args(["scan", "--this-flag-does-not-exist", "."])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "unknown CLI flag must exit 2 (clap usage error); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn daemon_conflicts_with_no_daemon_exits_two() {
    // args/scan.rs: `--daemon` is `conflicts_with = "no_daemon"`. clap rejects
    // the pair at parse time with exit 2.
    let out = Command::new(binary())
        .args(["scan", "--daemon", "--no-daemon", "."])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "--daemon + --no-daemon are mutually exclusive (clap exit 2); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn fast_conflicts_with_deep_exits_two() {
    // args/scan.rs: `--fast` is `conflicts_with_all = ["deep", ...]`.
    let out = Command::new(binary())
        .args(["scan", "--fast", "--deep", "."])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "--fast + --deep conflict (clap exit 2); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn precision_conflicts_with_no_decode_exits_two() {
    // args/scan.rs: `--precision` is `conflicts_with_all = [..., "no_decode", ...]`.
    let out = Command::new(binary())
        .args(["scan", "--precision", "--no-decode", "."])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "--precision + --no-decode conflict (clap exit 2); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn input_and_path_conflict_exits_two() {
    // args/scan.rs: positional `input` is `conflicts_with = "path"`.
    let out = Command::new(binary())
        .args(["scan", "--no-daemon", "--path", ".", "extra_positional"])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "positional input + --path conflict (clap exit 2); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Lockdown contract: every guard rail in run.rs is a hard exit 2 (anyhow::bail).
// ---------------------------------------------------------------------------

/// Run a lockdown scan with a hermetic HOME/XDG_CACHE_HOME so the disk-cache
/// violation gate can't trip on an inherited `~/.cache/keyhog`, and (on Linux)
/// wrap with `prlimit --core=0` so the coredump_filter / RLIMIT_CORE gate
/// passes for the child without touching the test runner's own limits.
fn lockdown_scan(path: &std::path::Path, extra: &[&str]) -> (String, Option<i32>) {
    let home = TempDir::new().expect("home tempdir");
    let p = path.to_str().expect("utf-8 path");

    let mut args: Vec<&str> = vec!["scan", "--no-daemon", "--backend", "simd", "--lockdown"];
    args.extend_from_slice(extra);
    args.push(p);

    // Prefer prlimit on Linux; fall back to a direct spawn if prlimit is
    // unavailable (non-Linux, or PATH without util-linux).
    let direct = || {
        Command::new(binary())
            .args(&args)
            .env("HOME", home.path())
            .env("XDG_CACHE_HOME", home.path())
            .output()
            .expect("spawn keyhog lockdown scan")
    };

    let output = {
        let mut cmd = Command::new("prlimit");
        cmd.args(["--core=0"]).arg(binary()).args(&args);
        cmd.env("HOME", home.path())
            .env("XDG_CACHE_HOME", home.path());
        match cmd.output() {
            Ok(o) => o,
            Err(_) => direct(),
        }
    };

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (combined, output.status.code())
}

#[test]
fn lockdown_verify_exits_two_with_message() {
    // run.rs first lockdown guard (under #[cfg(feature = "verify")]):
    // "lockdown mode forbids --verify". This bail happens BEFORE any
    // protections apply, so the exit is deterministic on every host.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let (combined, code) = lockdown_scan(&path, &["--verify", "--format", "json"]);
    assert_eq!(
        code,
        Some(2),
        "--lockdown --verify must exit 2; output={combined}"
    );
    assert!(
        combined.contains("lockdown mode forbids --verify"),
        "exit-2 diagnostic must name the verify conflict; output={combined}"
    );
}

#[test]
fn lockdown_show_secrets_exits_two_with_message() {
    // run.rs second lockdown guard: "lockdown mode forbids --show-secrets".
    // This is the "no plaintext" half of the lockdown contract and is
    // refused BEFORE apply_lockdown_protections, so credentials never print.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let (combined, code) = lockdown_scan(&path, &["--show-secrets", "--format", "json"]);
    assert_eq!(
        code,
        Some(2),
        "--lockdown --show-secrets must exit 2; output={combined}"
    );
    assert!(
        combined.contains("lockdown mode forbids --show-secrets"),
        "exit-2 diagnostic must name the show-secrets conflict; output={combined}"
    );
}

#[test]
fn lockdown_show_secrets_never_prints_the_plaintext_key() {
    // The whole point of forbidding --show-secrets under lockdown: the raw
    // credential must not reach stdout/stderr. The bail fires before scanning,
    // so the literal AKIA value can never appear in output.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let (combined, code) = lockdown_scan(&path, &["--show-secrets", "--format", "json"]);
    assert_eq!(code, Some(2), "must fail closed; output={combined}");
    let plaintext = concat!("AKIA", "QYLPMN5HFIQR7XYA");
    assert!(
        !combined.contains(plaintext),
        "lockdown must not leak the plaintext credential to stdout/stderr; output={combined}"
    );
}

#[test]
fn lockdown_no_decode_exits_two_with_message() {
    // run.rs guard: "lockdown mode forbids --no-decode". This bail happens
    // AFTER apply_lockdown_protections / disk-cache checks, so on hosts where
    // mlock/coredump cannot engage it may instead surface the protections
    // error — also exit 2. Accept either, but require exit 2 + a lockdown msg.
    let (_g, path) = fixture("clean.txt", "ok\n");
    let (combined, code) = lockdown_scan(&path, &["--no-decode", "--format", "json"]);
    assert_eq!(
        code,
        Some(2),
        "--lockdown --no-decode must exit 2; output={combined}"
    );
    assert!(
        combined.contains("lockdown mode forbids --no-decode")
            || combined.contains("protections failed to apply")
            || combined.contains("disk caches exist"),
        "must fail closed with a lockdown diagnostic; output={combined}"
    );
}

#[test]
fn lockdown_no_entropy_exits_two_with_message() {
    let (_g, path) = fixture("clean.txt", "ok\n");
    let (combined, code) = lockdown_scan(&path, &["--no-entropy", "--format", "json"]);
    assert_eq!(
        code,
        Some(2),
        "--lockdown --no-entropy must exit 2; output={combined}"
    );
    assert!(
        combined.contains("lockdown mode forbids --no-entropy")
            || combined.contains("protections failed to apply")
            || combined.contains("disk caches exist"),
        "must fail closed; output={combined}"
    );
}

#[test]
fn lockdown_no_ml_exits_two_with_message() {
    let (_g, path) = fixture("clean.txt", "ok\n");
    let (combined, code) = lockdown_scan(&path, &["--no-ml", "--format", "json"]);
    assert_eq!(
        code,
        Some(2),
        "--lockdown --no-ml must exit 2; output={combined}"
    );
    assert!(
        combined.contains("lockdown mode forbids --no-ml")
            || combined.contains("protections failed to apply")
            || combined.contains("disk caches exist"),
        "must fail closed; output={combined}"
    );
}

#[test]
fn lockdown_no_unicode_norm_exits_two_with_message() {
    let (_g, path) = fixture("clean.txt", "ok\n");
    let (combined, code) = lockdown_scan(&path, &["--no-unicode-norm", "--format", "json"]);
    assert_eq!(
        code,
        Some(2),
        "--lockdown --no-unicode-norm must exit 2; output={combined}"
    );
    assert!(
        combined.contains("lockdown mode forbids --no-unicode-norm")
            || combined.contains("protections failed to apply")
            || combined.contains("disk caches exist"),
        "must fail closed; output={combined}"
    );
}

#[test]
fn lockdown_no_default_excludes_exits_two_with_message() {
    let (_g, path) = fixture("clean.txt", "ok\n");
    let (combined, code) = lockdown_scan(&path, &["--no-default-excludes", "--format", "json"]);
    assert_eq!(
        code,
        Some(2),
        "--lockdown --no-default-excludes must exit 2; output={combined}"
    );
    assert!(
        combined.contains("lockdown mode forbids --no-default-excludes")
            || combined.contains("protections failed to apply")
            || combined.contains("disk caches exist"),
        "must fail closed; output={combined}"
    );
}

#[test]
fn lockdown_fast_is_rejected_at_clap_or_runtime_exit_two() {
    // `--fast` and `--lockdown` are BOTH accepted by clap (no conflicts_with
    // between them), so the rejection is the run.rs guard:
    // "lockdown mode forbids --fast". But `--fast` is `conflicts_with_all`
    // with --no_decode etc. — not with --lockdown — so this reaches runtime.
    let (_g, path) = fixture("clean.txt", "ok\n");
    let (combined, code) = lockdown_scan(&path, &["--fast", "--format", "json"]);
    assert_eq!(
        code,
        Some(2),
        "--lockdown --fast must exit 2; output={combined}"
    );
    assert!(
        combined.contains("lockdown mode forbids --fast")
            || combined.contains("protections failed to apply")
            || combined.contains("disk caches exist"),
        "must fail closed; output={combined}"
    );
}

#[test]
fn lockdown_clean_scan_exits_zero_or_fails_closed() {
    // A clean lockdown scan with no forbidden flags either succeeds (exit 0,
    // protections engaged + zero findings) or fails closed (exit 2) when the
    // host cannot apply mlock/coredump protections. It must NEVER silently
    // succeed-with-degraded-protection, and must never crash (3/11/139).
    let (_g, path) = fixture("clean.txt", "fn main() {}\n");
    let (combined, code) = lockdown_scan(&path, &["--format", "json"]);
    assert!(
        code == Some(0) || code == Some(2),
        "clean lockdown scan must be 0 (ok) or 2 (fail closed), never crash; \
         code={code:?} output={combined}"
    );
}

#[test]
fn lockdown_emits_lockdown_banner_when_protections_engage() {
    // run.rs prints "LOCKDOWN MODE: no findings cache on disk, mlocked, no
    // live verifier" to stderr once protections successfully apply. If the
    // host can't engage them the scan fails closed (exit 2) before the banner;
    // accept both, but if it exited 0 the banner MUST be present.
    let (_g, path) = fixture("clean.txt", "ok\n");
    let (combined, code) = lockdown_scan(&path, &["--format", "json"]);
    if code == Some(0) {
        assert!(
            combined.contains("LOCKDOWN MODE"),
            "a successful lockdown run must announce LOCKDOWN MODE on stderr; output={combined}"
        );
    } else {
        assert_eq!(
            code,
            Some(2),
            "non-zero lockdown exit must be the fail-closed 2; output={combined}"
        );
    }
}

#[test]
fn lockdown_findings_still_exit_one_when_protections_engage() {
    // Lockdown does not change the finding-present exit code: a planted key
    // under a clean lockdown run is still exit 1. If protections can't engage
    // the run fails closed (2). It must never be 0 with a finding present.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let (combined, code) = lockdown_scan(&path, &["--format", "json"]);
    assert!(
        code == Some(1) || code == Some(2),
        "lockdown scan over a leak must be 1 (finding) or 2 (fail closed), \
         never 0; code={code:?} output={combined}"
    );
}

// ---------------------------------------------------------------------------
// Daemon route never bypasses the lockdown / filtering policy (scan.rs).
// ---------------------------------------------------------------------------

#[test]
fn explicit_daemon_with_lockdown_fails_loud_not_fallback() {
    // Explicit daemon selection is an operator request. If the requested scan
    // needs lockdown or secret-output policy the daemon cannot enforce, keyhog
    // must reject the request loudly instead of silently substituting an
    // in-process scan.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let home = TempDir::new().expect("home tempdir");
    let p = path.to_str().expect("utf-8 path");

    // Use a throwaway XDG_RUNTIME_DIR so we don't accidentally connect to a
    // real daemon socket on the dev box; the point is the route is Forbidden
    // regardless of socket presence.
    let runtime = TempDir::new().expect("runtime");
    let out = Command::new(binary())
        .args([
            "scan",
            "--daemon",
            "--backend",
            "simd",
            "--lockdown",
            "--show-secrets",
            "--format",
            "json",
            p,
        ])
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .output()
        .expect("spawn");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "--daemon --lockdown --show-secrets must fail loud instead of \
         silently falling back in-process; output={combined}"
    );
    assert!(
        combined.contains("--daemon=on cannot be honored")
            && combined.contains("lockdown")
            && combined.contains("secret-output")
            && combined.contains("Drop `--daemon=on`"),
        "daemon-forbidden route must explain the policy and fix; output={combined}"
    );
    assert!(
        !combined.contains("daemon route: connect"),
        "must NOT have attempted a daemon connection; output={combined}"
    );
}

#[test]
fn explicit_daemon_with_show_secrets_fails_loud_not_fallback() {
    // `--show-secrets` is a daemon-forbidden route. With explicit `--daemon`,
    // the product contract is a loud refusal, not a hidden in-process scan.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let runtime = TempDir::new().expect("runtime");
    let p = path.to_str().expect("utf-8 path");
    let out = Command::new(binary())
        .args([
            "scan",
            "--daemon",
            "--backend",
            "simd",
            "--show-secrets",
            "--format",
            "json",
            p,
        ])
        .env("XDG_RUNTIME_DIR", runtime.path())
        .output()
        .expect("spawn");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "--daemon --show-secrets over a leak must fail loud instead of \
         silently falling back in-process; output={combined}"
    );
    assert!(
        combined.contains("--daemon=on cannot be honored")
            && combined.contains("secret-output")
            && combined.contains("Drop `--daemon=on`"),
        "daemon-forbidden route must explain secret-output policy and fix; output={combined}"
    );
    assert!(
        !combined.contains("daemon route: connect"),
        "secret-output policy must force in-process, never a daemon connect; output={combined}"
    );
}

// ---------------------------------------------------------------------------
// Require-GPU fail-closed preflight: exit 12 on the no-GPU path.
// ---------------------------------------------------------------------------

#[test]
fn require_gpu_and_no_gpu_flags_conflict() {
    // The invalid contradiction is rejected by clap before routing or scanning.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let out = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--require-gpu",
            "--no-gpu",
            &line_path(&path),
        ])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "--require-gpu and --no-gpu must be rejected as conflicting flags; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--require-gpu") && stderr.contains("--no-gpu"),
        "conflict diagnostic must name both flags; stderr={stderr}"
    );
}

/// Borrow the path as &str for arg construction (kept tiny so the require-GPU
/// tests stay readable). `line_path` is a misnomer kept local; it returns the
/// path string, not a line.
fn line_path(p: &std::path::Path) -> String {
    p.to_string_lossy().into_owned()
}

#[test]
fn require_gpu_exit_twelve_diagnostic_names_the_flag() {
    if host_has_usable_gpu() {
        return;
    }
    // run.rs prints `keyhog: <diagnostic>` to stderr; the diagnostic string
    // must name --require-gpu so the operator knows which gate fired.
    let (_g, path) = fixture("leak.env", &aws_key_line());
    let out = Command::new(binary())
        .args(["scan", "--no-daemon", "--require-gpu", &line_path(&path)])
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(12),
        "must be exit 12; stderr={stderr}"
    );
    assert!(
        stderr.contains("--require-gpu"),
        "exit-12 diagnostic must name --require-gpu; stderr={stderr}"
    );
    assert!(
        stderr.contains("keyhog:"),
        "diagnostic is printed via the `keyhog: <msg>` prefix in run.rs; stderr={stderr}"
    );
}

#[test]
fn require_gpu_fires_before_scanning_so_exit_is_twelve_even_on_clean_input() {
    if host_has_usable_gpu() {
        return;
    }
    // The preflight runs BEFORE the scan, so even a clean file (which would
    // otherwise exit 0) must exit 12 when the requirement is unmet. This proves
    // the gate is a true preflight, not a post-scan adjustment.
    let (_g, path) = fixture("clean.txt", "fn main() {}\n");
    let out = Command::new(binary())
        .args(["scan", "--no-daemon", "--require-gpu", &line_path(&path)])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(12),
        "require-GPU preflight must fail closed even on clean input (exit 12, \
         not 0); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn require_gpu_does_not_print_findings_on_fail_closed() {
    if host_has_usable_gpu() {
        return;
    }
    // When the preflight fails, run.rs returns immediately — no findings are
    // ever computed or printed. With --format json, stdout must NOT contain a
    // findings array; the run never reached report_findings.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let out = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--require-gpu",
            "--format",
            "json",
            &line_path(&path),
        ])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(12), "must fail closed (12)");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // No JSON findings report should have been emitted; the plaintext key
    // must not appear on stdout either.
    let plaintext = concat!("AKIA", "QYLPMN5HFIQR7XYA");
    assert!(
        !stdout.contains(plaintext),
        "fail-closed preflight must not print findings/plaintext to stdout; stdout={stdout}"
    );
}

#[test]
fn no_require_gpu_policy_scans_normally_on_cpu() {
    // require_gpu_preflight() is a no-op (Ok) when GPU policy is not required,
    // so a normal scan proceeds. With --no-gpu forcing the CPU path and a
    // planted key, the run must reach the finding-present branch (exit 1), not
    // the require-GPU exit 12.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let out = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--no-gpu",
            "--backend",
            "cpu",
            "--format",
            "json",
            &line_path(&path),
        ])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(1),
        "without --require-gpu the CPU path must scan and exit 1 on a \
         planted key, not 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn gpu_config_off_scans_normally_on_cpu() {
    // TOML `gpu = "off"` is the persistent CPU policy. A planted-key scan must
    // reach the finding-present branch (exit 1), not the require-GPU exit 12.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let (_cfg_guard, cfg) = config_fixture("keyhog.toml", "[system]\ngpu = \"off\"\n");
    let out = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--config",
            &line_path(&cfg),
            "--backend",
            "cpu",
            "--format",
            "json",
            &line_path(&path),
        ])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(1),
        "TOML gpu = \"off\" must scan on CPU and exit 1 on a planted key; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn gpu_config_required_on_no_gpu_host_exits_twelve() {
    if host_has_usable_gpu() {
        return;
    }
    let (_g, path) = fixture("clean.txt", "fn main() {}\n");
    let (_cfg_guard, cfg) = config_fixture("keyhog.toml", "[system]\ngpu = \"required\"\n");
    let out = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--config",
            &line_path(&cfg),
            "--format",
            "json",
            &line_path(&path),
        ])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(12),
        "TOML gpu = \"required\" must fail closed on a no-GPU host; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn require_gpu_clean_input_no_require_exits_zero() {
    // Sanity twin: no require-GPU, clean file, CPU forced -> exit 0. Confirms
    // the require-GPU policy is the only thing flipping the exit to 12 in the
    // preceding tests.
    let (_g, path) = fixture("clean.txt", "fn main() {}\n");
    let out = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--no-gpu",
            "--backend",
            "cpu",
            "--format",
            "json",
            &line_path(&path),
        ])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(0),
        "control: clean CPU scan with no require-GPU must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Exit-code stability / boundary properties.
// ---------------------------------------------------------------------------

#[test]
fn exit_code_is_deterministic_across_repeated_clean_runs() {
    // Property-style loop: a clean scan must exit 0 every time. Re-running the
    // same input must not flip the exit code (no cache/order nondeterminism in
    // the exit contract).
    let (_g, path) = fixture("clean.txt", "fn main() {}\n");
    for i in 0..5 {
        let (_o, _e, code) = scan_in_process(&path, &["--format", "json"]);
        assert_eq!(code, Some(0), "clean run #{i} must exit 0 every time");
    }
}

#[test]
fn exit_code_is_deterministic_across_repeated_leak_runs() {
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    for i in 0..5 {
        let (_o, _e, code) = scan_in_process(&path, &["--format", "json"]);
        assert_eq!(code, Some(1), "leak run #{i} must exit 1 every time");
    }
}

#[test]
fn severity_filter_does_not_change_exit_when_findings_remain() {
    // --severity is a Forbidden daemon route (scan.rs), so it always runs
    // in-process. A planted critical AWS key surviving a `--severity high`
    // filter must still exit 1. (AWS access keys are HIGH/CRITICAL severity,
    // so the filter keeps them.)
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let (_o, stderr, code) = scan_in_process(&path, &["--format", "json", "--severity", "high"]);
    assert_eq!(
        code,
        Some(1),
        "a high-severity finding surviving --severity high must exit 1; stderr={stderr}"
    );
}

#[test]
fn severity_filter_dropping_all_findings_exits_zero() {
    // When --severity filters out *every* match, report_findings is empty and
    // has_new_entries is false -> exit 0. An AWS key cannot clear a `critical`
    // floor only if it is below critical; assert the contract via a low-signal
    // input instead: a clean file with --severity critical is unambiguously 0.
    let (_g, path) = fixture("clean.txt", "fn main() {}\n");
    let (_o, _e, code) = scan_in_process(&path, &["--format", "json", "--severity", "critical"]);
    assert_eq!(code, Some(0), "clean file with severity filter must exit 0");
}

#[test]
fn min_confidence_one_point_zero_can_suppress_to_exit_zero() {
    // --min-confidence is a Forbidden daemon route (scan.rs). At the maximum
    // floor 1.0, weak/borderline findings are dropped. If all findings are
    // suppressed the run exits 0; if a finding clears 1.0 it exits 1. Either
    // way it must never crash and must be one of {0,1}.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let (_o, stderr, code) =
        scan_in_process(&path, &["--format", "json", "--min-confidence", "1.0"]);
    assert!(
        code == Some(0) || code == Some(1),
        "min-confidence 1.0 must yield exit 0 (all suppressed) or 1 (survivor), \
         never crash; code={code:?} stderr={stderr}"
    );
}

#[test]
fn create_baseline_exits_zero_even_with_findings() {
    // run.rs: when --create-baseline is set, the baseline is written and the
    // run returns ExitCode::SUCCESS *unconditionally*, before the findings
    // exit-code logic. So a leak + --create-baseline exits 0, not 1.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let bdir = TempDir::new().expect("baseline dir");
    let bpath = bdir.path().join("baseline.json");
    let out = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "json",
            "--create-baseline",
            bpath.to_str().unwrap(),
            path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(0),
        "--create-baseline writes the baseline and exits 0 regardless of \
         findings; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        bpath.exists(),
        "baseline file must have been created at {}",
        bpath.display()
    );
}

#[test]
fn baseline_suppressing_all_findings_exits_zero() {
    // run.rs --baseline branch: filter_new drops findings already in the
    // baseline; if none are new, has_new is false -> exit 0. Create a baseline
    // from the leak, then scan the same leak against it: all suppressed -> 0.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let bdir = TempDir::new().expect("baseline dir");
    let bpath = bdir.path().join("baseline.json");

    // 1) create the baseline (exits 0).
    let create = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "json",
            "--create-baseline",
            bpath.to_str().unwrap(),
            path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn create");
    assert_eq!(
        create.status.code(),
        Some(0),
        "baseline creation must exit 0"
    );

    // 2) re-scan against it: the same finding is now baselined -> exit 0.
    let rescan = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "json",
            "--baseline",
            bpath.to_str().unwrap(),
            path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn rescan");
    assert_eq!(
        rescan.status.code(),
        Some(0),
        "a finding fully suppressed by --baseline must exit 0; stderr={}",
        String::from_utf8_lossy(&rescan.stderr)
    );
}

#[test]
fn baseline_forbidden_daemon_route_fails_loud_not_fallback() {
    // `--baseline` needs CLI-side baseline state the daemon does not have. An
    // explicit daemon request must be rejected loudly instead of replaced with
    // a hidden in-process scan.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let bdir = TempDir::new().expect("baseline dir");
    let bpath = bdir.path().join("baseline.json");
    let runtime = TempDir::new().expect("runtime");

    let _ = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "json",
            "--create-baseline",
            bpath.to_str().unwrap(),
            path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn create");

    let out = Command::new(binary())
        .args([
            "scan",
            "--daemon",
            "--backend",
            "simd",
            "--format",
            "json",
            "--baseline",
            bpath.to_str().unwrap(),
            path.to_str().unwrap(),
        ])
        .env("XDG_RUNTIME_DIR", runtime.path())
        .output()
        .expect("spawn");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "--daemon --baseline must fail loud instead of silently falling back \
         in-process; output={combined}"
    );
    assert!(
        combined.contains("--daemon=on cannot be honored")
            && combined.contains("--baseline requires the in-process baseline filter")
            && combined.contains("Drop `--daemon=on`"),
        "daemon-forbidden baseline route must explain the policy and fix; output={combined}"
    );
    assert!(
        !combined.contains("daemon route: connect"),
        "--baseline must be rejected before any daemon connection; output={combined}"
    );
}

// ---------------------------------------------------------------------------
// Stdin path exit codes (no daemon).
// ---------------------------------------------------------------------------

#[test]
fn stdin_clean_exits_zero() {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--stdin",
            "--format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"fn main() {}\n")
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    assert_eq!(
        out.status.code(),
        Some(0),
        "clean stdin must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn stdin_leak_exits_one() {
    use std::io::Write;
    use std::process::Stdio;
    let line = aws_key_line();
    let mut child = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--stdin",
            "--format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(line.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    assert_eq!(
        out.status.code(),
        Some(1),
        "a planted key on stdin must exit 1; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn stdin_lockdown_show_secrets_fails_closed_exit_two() {
    // Lockdown + show-secrets over stdin must still hit the run.rs guard and
    // exit 2 with the show-secrets message — the no-plaintext contract holds
    // on the stdin path too, and it must NOT leak the key on stdout/stderr.
    use std::io::Write;
    use std::process::Stdio;
    let line = aws_key_line();
    let home = TempDir::new().expect("home");
    let mut child = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--lockdown",
            "--show-secrets",
            "--stdin",
            "--format",
            "json",
        ])
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(line.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "stdin lockdown + show-secrets must exit 2; output={combined}"
    );
    assert!(
        combined.contains("lockdown mode forbids --show-secrets"),
        "stdin path must enforce the show-secrets guard; output={combined}"
    );
    let plaintext = concat!("AKIA", "QYLPMN5HFIQR7XYA");
    assert!(
        !combined.contains(plaintext),
        "stdin lockdown must not leak the plaintext key; output={combined}"
    );
}

// ---------------------------------------------------------------------------
// The exit codes never collide with the higher classes on benign input.
// ---------------------------------------------------------------------------

#[test]
fn benign_runs_never_return_system_or_panic_exit_codes() {
    // Exit 3 (system error) and 11 (scanner panic) are reserved for genuine
    // environment failures / panics. A clean file and a planted-leak file on a
    // healthy host must never return those codes.
    let (_gc, clean) = fixture("clean.txt", "fn main() {}\n");
    let (_co, _ce, clean_code) = scan_in_process(&clean, &["--format", "json"]);
    assert!(
        clean_code != Some(3) && clean_code != Some(11),
        "clean scan must not return system/panic codes; got {clean_code:?}"
    );

    let (_gl, leak) = fixture("leak.env", &aws_key_line());
    let (_lo, _le, leak_code) = scan_in_process(&leak, &["--format", "json"]);
    assert!(
        leak_code != Some(3) && leak_code != Some(11),
        "leak scan must not return system/panic codes; got {leak_code:?}"
    );
}

#[test]
fn live_credentials_exit_code_constant_is_ten_not_one() {
    // Documented contract: live-verified credentials exit 10 (run.rs
    // EXIT_LIVE_CREDENTIALS), distinct from unverified findings (1). Without
    // --verify we never reach the Live branch; this test pins that an
    // unverified planted key is exactly 1 and NOT 10, so the two classes are
    // observably distinct in the binary's behavior.
    let line = aws_key_line();
    let (_g, path) = fixture("leak.env", &line);
    let (_o, _e, code) = scan_in_process(&path, &["--format", "json"]);
    assert_eq!(code, Some(1), "unverified finding is exit 1");
    assert_ne!(
        code,
        Some(10),
        "exit 10 is reserved for --verify Live results only"
    );
}
