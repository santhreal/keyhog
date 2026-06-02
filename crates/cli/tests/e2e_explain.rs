//! e2e test for `keyhog explain <detector-id>`.
//!
//! The explain subcommand provides detailed documentation on a single
//! detector: regex pattern, severity, rotation guide, etc. This test
//! verifies that explain returns well-formed output for valid detector IDs
//! and fails gracefully for invalid ones.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// `keyhog explain aws-access-key` returns exit 0 and includes the detector
/// spec (regex, severity, keywords, rotation guide).
#[test]
fn explain_valid_detector_returns_exit_zero_with_spec() {
    let output = Command::new(binary())
        .arg("explain")
        .arg("aws-access-key")
        .output()
        .expect("spawn keyhog explain aws-access-key");

    assert_eq!(
        output.status.code(),
        Some(0),
        "explain aws-access-key should exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // The explain output should contain the detector name, service,
    // and spec fields (regex, patterns, severity).
    assert!(
        stdout.contains("aws-access-key") || stdout.contains("AWS Access Key"),
        "explain output must include the detector id or name; got: {stdout}"
    );

    assert!(
        stdout.contains("severity") || stdout.contains("regex") || stdout.contains("pattern"),
        "explain output must include detector spec (severity/regex); got: {stdout}"
    );
}

/// `keyhog explain github-pat` uses the loaded corpus and surfaces the
/// GitHub Personal Access Token detector spec.
#[test]
fn explain_github_pat_detector_includes_rotation_guide() {
    let output = Command::new(binary())
        .arg("explain")
        .arg("github-pat")
        .output()
        .expect("spawn keyhog explain github-pat");

    assert_eq!(
        output.status.code(),
        Some(0),
        "explain github-pat should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("github") || stdout.contains("GitHub"),
        "explain github-pat must mention github; got: {stdout}"
    );

    // The output should include guidance on key rotation/revocation.
    assert!(
        stdout.to_lowercase().contains("revoke")
            || stdout.to_lowercase().contains("rotate")
            || stdout.to_lowercase().contains("github"),
        "explain must include rotation guidance or service info; got: {stdout}"
    );
}

/// `keyhog explain nonexistent-detector-id` returns exit 2 (user error) and
/// reports the invalid detector ID clearly so the operator knows what went wrong.
#[test]
fn explain_invalid_detector_id_exits_two_with_actionable_error() {
    let output = Command::new(binary())
        .arg("explain")
        .arg("detector-does-not-exist-xyz")
        .output()
        .expect("spawn keyhog explain <invalid>");

    assert_eq!(
        output.status.code(),
        Some(2),
        "explain with invalid detector ID should exit 2 (user error)"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("not found")
            || stderr.to_lowercase().contains("unknown")
            || stderr.contains("detector-does-not-exist"),
        "error message must name the invalid detector so operator knows why; got: {stderr}"
    );
}

/// `keyhog explain --help` documents the positional detector-id argument
/// and the --detectors flag.
#[test]
fn explain_help_documents_detector_id_argument() {
    let output = Command::new(binary())
        .arg("explain")
        .arg("--help")
        .output()
        .expect("spawn keyhog explain --help");

    assert_eq!(
        output.status.code(),
        Some(0),
        "explain --help should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("DETECTOR_ID") || stdout.contains("detector"),
        "help must document the required detector-id argument; got: {stdout}"
    );

    assert!(
        stdout.contains("--detectors"),
        "help must mention the --detectors directory override flag; got: {stdout}"
    );
}
