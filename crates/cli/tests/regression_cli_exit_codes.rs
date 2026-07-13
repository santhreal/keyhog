//! Regression suite: the CLI process **exit-code contract** across every scan
//! outcome, driven through the REAL shipped binary (`CARGO_BIN_EXE_keyhog`).
//!
//! The numeric codes are owned by `crate::exit_codes` (single source of truth):
//!   * `EXIT_SUCCESS`       = 0 (clean scan, no findings).
//!   * `EXIT_FINDINGS`      = 1 (secrets found, none confirmed live).
//!   * `EXIT_USER_ERROR`    = 2, bad flag/value, unknown subcommand, missing
//!                                 path (NotFound is a user I/O error); also the
//!                                 code clap uses for its own usage diagnostics.
//!   * `EXIT_SYSTEM_ERROR`  = 3, local environment failure (not asserted via a
//!                                 live path here; pinned as a constant).
//!   * `EXIT_LIVE_CREDENTIALS` = 10, a verified-live credential (requires
//!                                 `--verify`); an UNVERIFIED finding must never
//!                                 reach this code.
//!   * `EXIT_SOURCE_FAILED` = 13, a requested source produced incomplete
//!                                 coverage (fail-closed, not "clean").
//!
//! HOST-INDEPENDENCE: every scan runs `--backend cpu` (the `ci`-feature binary
//! ships without Hyperscan, so `--backend simd` fails closed with exit 3; the
//! cpu path exists on every host), so these codes do not depend on an
//! accelerator. No test asserts a GPU-only outcome.
//!
//! TEST-TRUTH: every assertion pins an EXACT `Option<i32>` process code, an
//! EXACT `u8` constant, or EXACT stdout bytes (never a shape (Law 6)).

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A GitHub classic PAT with a valid trailing CRC, proven by the format/backend
/// parity e2e to fire `github-classic-pat` (severity critical, service github)
/// on its own bytes on the cpu path. Split via `concat!` so this test file is
/// not itself a self-scan tripwire; a fabricated random body would checksum-fail
/// and yield ZERO findings, defeating the findings→exit-1 assertion.
const PLANTED: &str = concat!("ghp_", "1234567890123456789012345678902PDSiF");

/// Run `keyhog scan --daemon=off --backend cpu <extra…> <path>` hermetically,
/// returning `(exit code, stdout, stderr)`. `KEYHOG_BACKEND` is stripped so an
/// ambient env override cannot swing the backend out from under the test.
fn scan(path: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off", "--backend", "cpu"]);
    cmd.args(extra);
    cmd.arg(path);
    cmd.env_remove("KEYHOG_BACKEND");
    let out = cmd.output().expect("spawn keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A tempdir containing a single file with the given contents; returns the file
/// path (the tempdir is kept alive by the returned guard).
fn fixture(name: &str, contents: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(name);
    std::fs::write(&path, contents).expect("write fixture");
    (dir, path)
}

// ---------------------------------------------------------------------------
// CONSTANT CONTRACT, the numeric codes cannot drift from their documented values
// ---------------------------------------------------------------------------

#[test]
fn exit_code_constants_have_documented_numbers() {
    // Pure, host-independent pin of every code this suite exercises end to end,
    // plus the codes it references in doc-comments, so a renumber is caught even
    // if a live path stops reaching one of them.
    assert_eq!(keyhog::exit_codes::EXIT_SUCCESS, 0);
    assert_eq!(keyhog::exit_codes::EXIT_FINDINGS, 1);
    assert_eq!(keyhog::exit_codes::EXIT_USER_ERROR, 2);
    assert_eq!(keyhog::exit_codes::EXIT_SYSTEM_ERROR, 3);
    assert_eq!(keyhog::exit_codes::EXIT_LIVE_CREDENTIALS, 10);
    assert_eq!(keyhog::exit_codes::EXIT_SOURCE_FAILED, 13);
    // Semantic aliases must resolve to their base numbers, not diverge.
    assert_eq!(
        keyhog::exit_codes::EXIT_CREDENTIALS_FOUND,
        keyhog::exit_codes::EXIT_FINDINGS
    );
}

// ---------------------------------------------------------------------------
// 0, clean scan
// ---------------------------------------------------------------------------

#[test]
fn clean_scan_exits_success_zero() {
    // Prose with no credential-bridge keywords (secret/key/token/password/api)
    // fires nothing → a true negative → exit 0.
    let (_d, path) = fixture("notes.txt", "just ordinary prose with plain words here\n");
    let (code, _out, err) = scan(&path, &["--format", "json"]);
    assert_eq!(code, Some(0), "clean tree must exit 0; stderr={err}");
}

#[test]
fn clean_scan_json_is_exactly_empty_array() {
    // A clean json run must be EXACTLY the two-byte bracket pair, the honest
    // empty shape, not a fail-closed empty stdout.
    let (_d, path) = fixture("notes.txt", "nothing sensitive at all in this file\n");
    let (code, out, err) = scan(&path, &["--format", "json"]);
    assert_eq!(code, Some(0), "clean json scan must exit 0; stderr={err}");
    assert_eq!(
        out.trim_end(),
        "[]",
        "clean json run must be exactly the empty array, got: {out:?}"
    );
}

// ---------------------------------------------------------------------------
// 1, findings present (and NEVER 10 without --verify)
// ---------------------------------------------------------------------------

#[test]
fn planted_valid_token_exits_findings_one() {
    // A checksum-valid GitHub PAT fires github-classic-pat; unverified → exit 1.
    let (_d, path) = fixture("dump.txt", &format!("{PLANTED}\n"));
    let (code, _out, err) = scan(&path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(1),
        "a planted valid token is findings→exit 1; stderr={err}"
    );
}

#[test]
fn planted_unverified_token_never_exits_live_ten() {
    // Without `--verify` the finding is verification=Skipped, so the live path
    // (exit 10) must NOT fire (a found-but-unverified secret is exit 1, not 10).
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={PLANTED}\n"));
    let (code, _out, err) = scan(&path, &["--format", "json"]);
    assert_ne!(
        code,
        Some(10),
        "an unverified finding must never surface as a live credential; stderr={err}"
    );
    assert_eq!(
        code,
        Some(1),
        "unverified planted secret is findings→exit 1, never live→10; stderr={err}"
    );
}

// ---------------------------------------------------------------------------
// 2, user error (bad path / bad value / bad args)
// ---------------------------------------------------------------------------

#[test]
fn missing_path_exits_user_error_two() {
    // A named path that does not exist is NotFound → a user I/O error → exit 2.
    let missing = PathBuf::from("/keyhog-exit-codes-no-such-path-9f8e7d6c");
    let (code, _out, err) = scan(&missing, &["--format", "json"]);
    assert_eq!(
        code,
        Some(2),
        "a nonexistent path is a user error → exit 2; stderr={err}"
    );
}

#[test]
fn missing_path_error_emits_empty_stdout() {
    // The fail-closed setup-error path writes the diagnostic to STDERR and exits
    // via `exit_now` before any report is produced: stdout must be empty (no
    // misleading `[]` "clean" array on an error).
    let missing = PathBuf::from("/keyhog-exit-codes-no-such-path-1a2b3c4d");
    let (code, out, err) = scan(&missing, &["--format", "json"]);
    assert_eq!(code, Some(2), "missing path → exit 2; stderr={err}");
    assert_eq!(
        out, "",
        "a fail-closed setup error must emit EMPTY stdout, got: {out:?}"
    );
    assert!(
        err.contains("error"),
        "the diagnostic must land on stderr; stderr={err}"
    );
}

#[test]
fn unknown_backend_value_exits_user_error_two() {
    // `--backend quantum` is rejected by clap's PossibleValuesParser → the
    // usage-error exit code, 2.
    let (_d, path) = fixture("clean.txt", "hello world\n");
    // Bypass the helper's fixed `--backend cpu` so the bad value is the ONLY one.
    let out = Command::new(binary())
        .args(["scan", "--daemon=off", "--backend", "quantum"])
        .arg(&path)
        .env_remove("KEYHOG_BACKEND")
        .output()
        .expect("spawn keyhog scan");
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unknown --backend value is a user error → exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn unknown_flag_exits_user_error_two() {
    // An undefined flag is a clap usage error → exit 2.
    let (_d, path) = fixture("clean.txt", "hello world\n");
    let (code, _out, err) = scan(&path, &["--this-flag-does-not-exist"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown flag is a usage error → exit 2; stderr={err}"
    );
}

#[test]
fn unknown_subcommand_exits_user_error_two() {
    // An unrecognized subcommand is a clap usage error → exit 2.
    let out = Command::new(binary())
        .arg("frobnicate-the-widgets")
        .output()
        .expect("spawn keyhog");
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unknown subcommand is a usage error → exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// 13, source failed / incomplete coverage (fail closed, NOT "clean")
// ---------------------------------------------------------------------------

#[test]
fn malformed_har_exits_source_failed_thirteen() {
    // A truncated HAR parses only as raw text (partial coverage): derived
    // request/response/body chunks are never expanded, so with no findings the
    // scan must fail closed with EXIT_SOURCE_FAILED (13), not report "clean" (0).
    let (_d, path) = fixture(
        "broken.har",
        r#"{"log": {"entries": [{"request": {"method": "GET", "url": "https://example.test", "headers": [{"name": "X-Key", "value": "har-cli-exitcode-marker"}]"#,
    );
    let (code, _out, err) = scan(&path, &["--progress", "--format", "json"]);
    assert_eq!(
        code,
        Some(13),
        "incomplete structured coverage must fail closed → exit 13; stderr={err}"
    );
}

// ---------------------------------------------------------------------------
// 0, non-scan surfaces that must exit cleanly
// ---------------------------------------------------------------------------

#[test]
fn version_flag_exits_zero() {
    let out = Command::new(binary())
        .arg("--version")
        .output()
        .expect("spawn keyhog --version");
    assert_eq!(
        out.status.code(),
        Some(0),
        "--version must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("KeyHog v"),
        "--version stdout must carry the version banner"
    );
}

#[test]
fn help_flag_exits_zero() {
    // clap renders help and exits 0 (DisplayHelp), distinct from the usage-error 2.
    let out = Command::new(binary())
        .arg("--help")
        .output()
        .expect("spawn keyhog --help");
    assert_eq!(
        out.status.code(),
        Some(0),
        "--help must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn no_args_prints_help_exits_zero() {
    // A bare invocation prints top-level help and returns success (not a usage
    // error): the `None` command arm calls `print_help` then returns SUCCESS.
    let out = Command::new(binary())
        .output()
        .expect("spawn keyhog with no args");
    assert_eq!(
        out.status.code(),
        Some(0),
        "bare invocation prints help → exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}
