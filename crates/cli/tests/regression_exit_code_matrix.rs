//! Full CLI exit-code MATRIX, pinned end to end through the real binary.
//!
//! `regression_exit_code_contract.rs` unit-tests the pure
//! `orchestrator::scan_exit_code` live-vs-not-live decision and pins the live
//! path (exit 10) e2e. This suite is the complementary half: it drives the
//! REAL binary through every *documented, always-reachable* exit class and
//! asserts the exact process code
//!
//!   * clean scan            -> 0   (`EXIT_SUCCESS`)
//!   * unverified findings   -> 1   (`EXIT_FINDINGS`, never 10 without `--verify`)
//!   * bad path / bad arg    -> 2   (`EXIT_USER_ERROR` / clap usage error)
//!   * `--help` / `--version`-> 0   (clap help/version)
//!
//! HOST-INDEPENDENCE (deliberate): every scan here forces `--backend cpu`
//! (`ScanBackend::CpuFallback`: "pure scalar AC + regex, works everywhere").
//! It is NOT gated on an accelerator, so `clean -> 0` and `findings -> 1` hold
//! byte-identically on a no-Hyperscan / no-GPU CI runner. A prior round shipped
//! `--backend simd` exit assertions that are host-flaky (they fail closed with
//! exit 3 when the SIMD feature is absent); this suite never asserts an
//! accelerator-only code. The only fail-closed code we DO exercise (exit 2) is
//! host-independent: a missing path or an unparseable flag is a user error on
//! every host.
//!
//! TEST-TRUTH: every assertion pins an EXACT `Option<i32>` process exit code, an
//! EXACT `u8` constant, or an EXACT substring of the rendered help, never a
//! shape (Law 6). `is_empty()`/`len()>0` are never the sole assertion.

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

// The documented codes, restated as literals so this test fails if a production
// constant silently drifts (the constants themselves are asserted separately in
// `exit_code_constants_match_documented_numbers`).
const EXIT_SUCCESS: i32 = 0;
const EXIT_FINDINGS: i32 = 1;
const EXIT_USER_ERROR: i32 = 2;
const EXIT_LIVE: i32 = 10;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A GitHub classic PAT with a valid CRC tail, split with `concat!` so this
/// test file is not itself a self-scan tripwire. Fires `github-classic-pat`.
/// (Identical construction to `regression_exit_code_contract.rs`, which proves
/// it detects under `--backend simd`; here we prove the SAME token under the
/// host-independent `cpu` backend.)
const PLANTED: &str = concat!("ghp_", "1234567890123456789012345678902PDSiF");

/// Run `keyhog scan --daemon=off --backend <backend> <extra…> <path>`
/// hermetically: the daemon route is disabled and every ambient backend/gpu env
/// override is stripped so the forced backend is the only routing input.
fn scan_with(backend: &str, path: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off", "--backend", backend]);
    cmd.args(extra);
    cmd.arg(path);
    cmd.env_remove("KEYHOG_BACKEND");
    cmd.env_remove("KEYHOG_REQUIRE_GPU");
    let out = cmd.output().expect("spawn keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Convenience wrapper defaulting to the pure-scalar `cpu` backend.
fn scan(path: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
    scan_with("cpu", path, extra)
}

// ---------------------------------------------------------------------------
// CODE 0, clean scans
// ---------------------------------------------------------------------------

#[test]
fn clean_scan_cpu_backend_exits_zero() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.rs");
    std::fs::write(&path, "fn main() { println!(\"no secrets here\"); }\n").expect("write clean");
    let (code, _stdout, stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(EXIT_SUCCESS),
        "a secret-free tree scanned on the host-independent cpu backend must exit 0; stderr={stderr}"
    );
}

#[test]
fn clean_scan_cpu_fallback_alias_also_exits_zero() {
    // `cpu` and `cpu-fallback` are advertised aliases of the same
    // `ScanBackend::CpuFallback`; the alias must resolve identically (no silent
    // fall-through to autoroute), so a clean tree is still exactly 0.
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, "the quick brown fox jumps over the lazy dog\n").expect("write clean");
    let (code, _stdout, stderr) = scan_with("cpu-fallback", &path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(EXIT_SUCCESS),
        "the cpu-fallback backend alias must behave identically to cpu (clean -> 0); stderr={stderr}"
    );
}

// ---------------------------------------------------------------------------
// CODE 1, findings, and the live-code boundary
// ---------------------------------------------------------------------------

#[test]
fn planted_secret_cpu_backend_exits_one() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("leak.env");
    std::fs::write(&path, format!("GITHUB_TOKEN={PLANTED}\n")).expect("write planted");
    let (code, _stdout, stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(EXIT_FINDINGS),
        "a detected-but-unverified secret is findings -> exit 1 on the cpu backend; stderr={stderr}"
    );
}

#[test]
fn planted_secret_without_verify_never_exits_ten() {
    // Guard the two-class collapse: without `--verify` the finding is
    // verification=Skipped, so the live-credentials code (10) must NOT fire.
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("leak.env");
    std::fs::write(&path, format!("token = \"{PLANTED}\"\n")).expect("write planted");
    let (code, _stdout, stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(EXIT_FINDINGS),
        "unverified finding must be 1, not 10; stderr={stderr}"
    );
    assert_ne!(
        code,
        Some(EXIT_LIVE),
        "exit 10 requires --verify; an unverified finding must never claim a live credential"
    );
}

#[test]
fn planted_secret_json_names_the_detector_and_exits_one() {
    // A stronger truth than the code alone: the cpu backend actually attributes
    // the leak to `github-classic-pat` (not merely "something non-empty"), and
    // the exit code agrees with the reported finding.
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("leak.conf");
    std::fs::write(&path, format!("gh={PLANTED}\n")).expect("write planted");
    let (code, stdout, stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(EXIT_FINDINGS),
        "planted PAT -> exit 1; stderr={stderr}"
    );
    assert!(
        stdout.contains("github-classic-pat"),
        "cpu backend must attribute the leak to github-classic-pat; stdout=\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// CODE 2, user errors: bad path (runtime) and bad args (clap usage)
// ---------------------------------------------------------------------------

#[test]
fn missing_path_cpu_backend_exits_two() {
    let missing = PathBuf::from("/keyhog-exit-matrix-no-such-path-9f8e7d6c5b4a");
    let (code, _stdout, stderr) = scan(&missing, &["--format", "json"]);
    assert_eq!(
        code,
        Some(EXIT_USER_ERROR),
        "a named path that does not exist is a user error -> exit 2; stderr={stderr}"
    );
}

#[test]
fn unknown_backend_value_exits_two() {
    // clap `PossibleValuesParser` rejects an out-of-set backend before any scan
    // runs; that is a usage error -> exit 2, host-independent.
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, "nothing sensitive\n").expect("write clean");
    let (code, _stdout, stderr) = scan_with("quantum-warp", &path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(EXIT_USER_ERROR),
        "an unknown --backend value is a clap usage error -> exit 2; stderr={stderr}"
    );
}

#[test]
fn invalid_format_value_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, "nothing sensitive\n").expect("write clean");
    // `--format` is a value_enum; an out-of-set value is rejected by clap.
    let (code, _stdout, stderr) = scan(&path, &["--format", "yaml-but-not-real"]);
    assert_eq!(
        code,
        Some(EXIT_USER_ERROR),
        "an unknown --format value is a clap usage error -> exit 2; stderr={stderr}"
    );
}

#[test]
fn unknown_flag_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, "nothing sensitive\n").expect("write clean");
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off", "--this-flag-does-not-exist"]);
    cmd.arg(&path);
    let out = cmd.output().expect("spawn keyhog scan");
    assert_eq!(
        out.status.code(),
        Some(EXIT_USER_ERROR),
        "an unrecognized flag is a clap usage error -> exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn unknown_subcommand_exits_two() {
    let out = Command::new(binary())
        .args(["definitely-not-a-subcommand"])
        .output()
        .expect("spawn keyhog");
    assert_eq!(
        out.status.code(),
        Some(EXIT_USER_ERROR),
        "an unknown subcommand is a clap usage error -> exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// CODE 0, help / version terminate cleanly
// ---------------------------------------------------------------------------

#[test]
fn top_level_help_exits_zero_and_renders_exit_codes_block() {
    let out = Command::new(binary())
        .arg("--help")
        .output()
        .expect("spawn keyhog --help");
    assert_eq!(
        out.status.code(),
        Some(EXIT_SUCCESS),
        "--help must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The help is generated from `exit_codes::DEFINITIONS`, so the EXIT CODES:
    // table (and the documented findings line) must appear verbatim, coherence
    // between the printed help and the numeric matrix this file pins.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("EXIT CODES:"),
        "top-level --help must render the EXIT CODES: block; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Secrets found"),
        "the exit-1 (findings) row must be documented in --help; stdout=\n{stdout}"
    );
}

#[test]
fn scan_subcommand_help_exits_zero() {
    let out = Command::new(binary())
        .args(["scan", "--help"])
        .output()
        .expect("spawn keyhog scan --help");
    assert_eq!(
        out.status.code(),
        Some(EXIT_SUCCESS),
        "scan --help must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("EXIT CODES:"),
        "scan --help carries the exit-code contract (after_help); stdout=\n{stdout}"
    );
}

#[test]
fn version_flag_exits_zero() {
    let out = Command::new(binary())
        .arg("--version")
        .output()
        .expect("spawn keyhog --version");
    assert_eq!(
        out.status.code(),
        Some(EXIT_SUCCESS),
        "--version must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("KeyHog v"),
        "--version prints the version banner; stdout=\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// The constants that back the matrix
// ---------------------------------------------------------------------------

#[test]
fn exit_code_constants_match_documented_numbers() {
    // Pin the numeric contract so the literals used above cannot silently drift
    // from the production constants (Law: ONE PLACE for every value).
    assert_eq!(keyhog::exit_codes::EXIT_SUCCESS, 0);
    assert_eq!(keyhog::exit_codes::EXIT_FINDINGS, 1);
    assert_eq!(keyhog::exit_codes::EXIT_USER_ERROR, 2);
    assert_eq!(keyhog::exit_codes::EXIT_SYSTEM_ERROR, 3);
    assert_eq!(keyhog::exit_codes::EXIT_HEALTH_FAILURE, 4);
    assert_eq!(keyhog::exit_codes::EXIT_LIVE_CREDENTIALS, 10);
    assert_eq!(keyhog::exit_codes::EXIT_INTERRUPTED, 130);
    // `CREDENTIALS_FOUND` is the alias the scan subcommand returns for findings;
    // it MUST equal the documented findings code (1), or a leak would exit with
    // an undocumented number.
    assert_eq!(
        keyhog::exit_codes::EXIT_CREDENTIALS_FOUND,
        keyhog::exit_codes::EXIT_FINDINGS
    );
    // The literals this file asserts against equal the production constants.
    assert_eq!(EXIT_SUCCESS, i32::from(keyhog::exit_codes::EXIT_SUCCESS));
    assert_eq!(EXIT_FINDINGS, i32::from(keyhog::exit_codes::EXIT_FINDINGS));
    assert_eq!(
        EXIT_USER_ERROR,
        i32::from(keyhog::exit_codes::EXIT_USER_ERROR)
    );
    assert_eq!(
        EXIT_LIVE,
        i32::from(keyhog::exit_codes::EXIT_LIVE_CREDENTIALS)
    );
}

#[test]
fn success_and_findings_codes_are_distinct() {
    // The most damaging exit-code regression is collapsing "clean" and "found":
    // a CI gate keyed on nonzero would then never fail on a real leak. Pin that
    // 0 and 1 are different both as constants and as the codes the binary emits
    // for clean vs. planted trees.
    assert_ne!(
        keyhog::exit_codes::EXIT_SUCCESS,
        keyhog::exit_codes::EXIT_FINDINGS,
        "clean and findings must be different exit codes"
    );

    let dir = TempDir::new().expect("tempdir");
    let clean = dir.path().join("clean.txt");
    std::fs::write(&clean, "just some prose, no secrets\n").expect("write clean");
    let (clean_code, _o1, e1) = scan(&clean, &["--format", "json"]);

    let leak = dir.path().join("leak.env");
    std::fs::write(&leak, format!("API={PLANTED}\n")).expect("write leak");
    let (leak_code, _o2, e2) = scan(&leak, &["--format", "json"]);

    assert_eq!(clean_code, Some(EXIT_SUCCESS), "clean -> 0; stderr={e1}");
    assert_eq!(leak_code, Some(EXIT_FINDINGS), "leak -> 1; stderr={e2}");
    assert_ne!(
        clean_code, leak_code,
        "clean and leaking trees must not share an exit code"
    );
}
