//! Contract: `scan --help` documents authoritative verification toggles when enabled.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Regression: Marketplace `verify: false` needs a discoverable negative CLI
/// switch whose help states that it overrides committed `verify = true`.
#[test]
fn scan_help_lists_positive_and_negative_verify_flags() {
    let output = Command::new(binary())
        .args(["scan", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--verify") && stdout.contains("--no-verify"),
        "scan help must document --verify and --no-verify; got: {stdout}"
    );
    assert!(
        stdout.contains("overriding `verify = true` in `.keyhog.toml`")
            || stdout.contains("overriding verify = true in .keyhog.toml"),
        "--no-verify help must explain committed-config precedence; got: {stdout}"
    );
}

/// Regression: accepting both verification switches would leave the effective
/// network policy order-dependent instead of failing contradictory input.
#[test]
fn positive_and_negative_verify_flags_conflict() {
    let output = Command::new(binary())
        .args(["scan", "--verify", "--no-verify", "."])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "clap must reject contradictory verification policy; stderr={stderr}"
    );
}
