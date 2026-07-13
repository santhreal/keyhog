//! Regression suite for the CLI scan exit-code contract, focused on the
//! `EXIT_LIVE_CREDENTIALS` (10) wiring.
//!
//! Background: `run()` maps the *reported* findings set to a process exit code.
//! The pure decision "any reported finding is `VerificationResult::Live` → 10,
//! else 0" is factored into `orchestrator::scan_exit_code`, reached here through
//! the `crate::testing` facade (`CliTestApi::scan_exit_code`). Unit-testing the
//! pure helper pins the live-vs-not-live boundary for EVERY verification state
//! without spawning a scan or needing a live provider; a handful of real-binary
//! e2e cases pin the surrounding documented codes (clean → 0, findings → 1,
//! bad flag/path → 2, doctor → 0) so a regression that collapses two exit
//! classes is caught end to end.
//!
//! Every assertion pins an EXACT `u8` code, an EXACT `Option<i32>` process exit
//! code, or an EXACT documented help string (never a shape (Law 6)).

use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::VerificationResult as V;
use keyhog_core::{MatchLocation, Severity, VerifiedFinding};
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tempfile::TempDir;

// The exit codes the contract pins, restated as literals so the test fails if
// the production constant drifts (the constant itself is separately asserted).
const EXIT_SUCCESS: u8 = 0;
const EXIT_LIVE: u8 = 10;

/// Build a `VerifiedFinding` carrying the given verification state. Only
/// `verification` matters to `scan_exit_code`; the rest is fixed, valid filler.
fn finding(verification: V) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("github-classic-pat"),
        detector_name: Arc::from("GitHub Classic PAT"),
        service: Arc::from("github"),
        severity: Severity::Critical,
        credential_redacted: Cow::Borrowed("ghp_...DSiF"),
        credential_hash: [0u8; 32].into(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("leak.env")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification,
        metadata: std::collections::HashMap::new(),
        additional_locations: Vec::new(),
        confidence: Some(0.9),
    }
}

// ---------------------------------------------------------------------------
// PURE HELPER: scan_exit_code(findings) -> u8
// ---------------------------------------------------------------------------

#[test]
fn empty_findings_yield_success_code() {
    // A clean scan reports nothing → no live credential → 0.
    assert_eq!(API.scan_exit_code(&[]), EXIT_SUCCESS);
}

#[test]
fn single_live_finding_yields_ten() {
    let findings = [finding(V::Live)];
    assert_eq!(API.scan_exit_code(&findings), EXIT_LIVE);
}

#[test]
fn skipped_finding_yields_success_not_live() {
    // `Skipped` is the DEFAULT state when `--verify` is off: a found-but-not-
    // verified secret must NEVER be reported as a live credential (that is the
    // findings=exit-1 case, decided by the caller, not this helper).
    let findings = [finding(V::Skipped)];
    assert_eq!(API.scan_exit_code(&findings), EXIT_SUCCESS);
}

#[test]
fn dead_finding_yields_success() {
    let findings = [finding(V::Dead)];
    assert_eq!(API.scan_exit_code(&findings), EXIT_SUCCESS);
}

#[test]
fn revoked_finding_yields_success() {
    // A credential that verified as explicitly revoked is valid-but-inactive:
    // it is NOT live, so it does not trip the live exit code.
    let findings = [finding(V::Revoked)];
    assert_eq!(API.scan_exit_code(&findings), EXIT_SUCCESS);
}

#[test]
fn rate_limited_finding_yields_success() {
    let findings = [finding(V::RateLimited)];
    assert_eq!(API.scan_exit_code(&findings), EXIT_SUCCESS);
}

#[test]
fn error_finding_yields_success() {
    // Verification that failed with a network/timeout error is UNKNOWN, not
    // live (failing it into the live class would be a false "live" alarm).
    let findings = [finding(V::Error("connection reset".to_string()))];
    assert_eq!(API.scan_exit_code(&findings), EXIT_SUCCESS);
}

#[test]
fn unverifiable_finding_yields_success() {
    let findings = [finding(V::Unverifiable)];
    assert_eq!(API.scan_exit_code(&findings), EXIT_SUCCESS);
}

#[test]
fn one_live_among_non_live_still_yields_ten() {
    // A single live credential mixed with dead/skipped findings must trip 10:
    // the operator has an active secret regardless of the others.
    let findings = [finding(V::Dead), finding(V::Live), finding(V::Skipped)];
    assert_eq!(API.scan_exit_code(&findings), EXIT_LIVE);
}

#[test]
fn all_non_live_mix_yields_success() {
    // Every non-live state combined still resolves to 0, there is no live
    // credential in the set.
    let findings = [
        finding(V::Dead),
        finding(V::Skipped),
        finding(V::Revoked),
        finding(V::RateLimited),
        finding(V::Unverifiable),
        finding(V::Error("timeout".to_string())),
    ];
    assert_eq!(API.scan_exit_code(&findings), EXIT_SUCCESS);
}

#[test]
fn multiple_live_findings_yield_ten() {
    let findings = [finding(V::Live), finding(V::Live)];
    assert_eq!(API.scan_exit_code(&findings), EXIT_LIVE);
}

#[test]
fn live_as_last_element_is_detected() {
    // Guards against a short-circuit-order bug: the live finding is last.
    let findings = [
        finding(V::Skipped),
        finding(V::Dead),
        finding(V::Revoked),
        finding(V::Live),
    ];
    assert_eq!(API.scan_exit_code(&findings), EXIT_LIVE);
}

// ---------------------------------------------------------------------------
// EXIT-CODE CONSTANT + HELP CONTRACT
// ---------------------------------------------------------------------------

#[test]
fn exit_code_constants_have_documented_numbers() {
    assert_eq!(keyhog::exit_codes::EXIT_SUCCESS, 0);
    assert_eq!(keyhog::exit_codes::EXIT_FINDINGS, 1);
    assert_eq!(keyhog::exit_codes::EXIT_USER_ERROR, 2);
    assert_eq!(keyhog::exit_codes::EXIT_LIVE_CREDENTIALS, 10);
    // The helper's literals must match the production constants exactly.
    assert_eq!(EXIT_LIVE, keyhog::exit_codes::EXIT_LIVE_CREDENTIALS);
    assert_eq!(EXIT_SUCCESS, keyhog::exit_codes::EXIT_SUCCESS);
}

#[test]
fn exit_code_definitions_document_live_requires_verify() {
    let live = keyhog::exit_codes::DEFINITIONS
        .iter()
        .find(|d| d.code == 10)
        .expect("exit code 10 must be documented in DEFINITIONS");
    assert_eq!(live.label, "Live credentials found");
    assert_eq!(live.help, "Live credentials found (requires --verify)");
    assert!(
        live.scan_reachable,
        "exit 10 is reachable from a scan run (with --verify)"
    );
    // The rendered `EXIT CODES:` help block is generated from DEFINITIONS, so
    // the documented "requires --verify" line must appear verbatim.
    assert!(
        keyhog::exit_codes::help().contains("Live credentials found (requires --verify)"),
        "help text must document the live-credentials exit code"
    );
}

// ---------------------------------------------------------------------------
// REAL-BINARY E2E: the documented surrounding exit codes
// ---------------------------------------------------------------------------

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A GitHub classic PAT with a valid CRC tail, split so this test file is not
/// itself a self-scan tripwire. Fires `github-classic-pat` at confidence 0.9.
const PLANTED: &str = concat!("ghp_", "1234567890123456789012345678902PDSiF");

/// Run `keyhog scan --daemon=off --backend simd <extra…> <path>` hermetically.
fn scan(path: &Path, extra: &[&str]) -> (Option<i32>, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off"]);
    if !extra.contains(&"--backend") {
        cmd.args(["--backend", "simd"]);
    }
    cmd.args(extra);
    cmd.arg(path);
    cmd.env_remove("KEYHOG_BACKEND");
    let out = cmd.output().expect("spawn keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn e2e_clean_scan_exits_zero() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.rs");
    std::fs::write(&path, "fn main() { println!(\"no secrets\"); }\n").expect("write clean");
    let (code, stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(code, Some(0), "clean tree must exit 0; stderr={stderr}");
}

#[test]
fn e2e_planted_unverified_finding_exits_one_never_ten() {
    // A found-but-unverified secret (no `--verify`) is verification=Skipped, so
    // the live-credential path must NOT fire: exit 1 (findings), not 10.
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("leak.env");
    std::fs::write(&path, format!("GITHUB_TOKEN={PLANTED}\n")).expect("write planted");
    let (code, stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(1),
        "unverified planted secret is findings→exit 1, never live→10; stderr={stderr}"
    );
    assert_ne!(
        code,
        Some(10),
        "an unverified finding must never surface as a live credential"
    );
}

#[test]
fn e2e_missing_path_exits_two() {
    let missing = PathBuf::from("/keyhog-exit-contract-no-such-path-a1b2c3");
    let (code, stderr) = scan(&missing, &["--format", "json"]);
    assert_eq!(
        code,
        Some(2),
        "a named path that does not exist is a user error → exit 2; stderr={stderr}"
    );
}

#[test]
fn e2e_invalid_backend_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, "hello world\n").expect("write clean");
    let (code, stderr) = scan(&path, &["--backend", "quantum"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown --backend value is a user error → exit 2; stderr={stderr}"
    );
}

#[test]
fn e2e_doctor_exits_zero_on_healthy_host() {
    let output = Command::new(binary())
        .arg("doctor")
        .output()
        .expect("run keyhog doctor");
    assert_eq!(
        output.status.code(),
        Some(0),
        "doctor must exit 0 on a healthy host; stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
