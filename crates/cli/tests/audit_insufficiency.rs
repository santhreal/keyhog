//! Black-box contract: invalid scanner policy is rejected, never normalized.
//!
//! `config --effective` is the operator's source of truth for what a scan will
//! run. Invalid ML weights and impossible Shannon-entropy thresholds must fail
//! at the CLI boundary instead of being clamped into a different policy before
//! that surface is rendered.

use std::path::PathBuf;
use std::process::{Command, Output};

fn binary() -> PathBuf {
    let cargo_bin = PathBuf::from(env!("CARGO_BIN_EXE_keyhog"));
    if cargo_bin.exists() {
        return cargo_bin;
    }
    let prebuilt =
        PathBuf::from("/mnt/FlareTraining/santh-archive/cargo-target/release-fast/keyhog");
    if prebuilt.exists() {
        return prebuilt;
    }
    cargo_bin
}

fn run_effective(extra_args: &[&str]) -> Output {
    let dir = tempfile::tempdir().expect("create temp dir");
    let target = dir.path().join("f.txt");
    std::fs::write(&target, b"x = 1\n").expect("write scan target");

    let mut args = vec!["config", "--effective", "--no-gpu"];
    args.extend_from_slice(extra_args);
    Command::new(binary())
        .args(args)
        .arg(target)
        .output()
        .expect("spawn keyhog")
}

fn assert_policy_rejected(args: &[&str], field: &str, range: &str) {
    let output = run_effective(args);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid {field} must be a usage error; stderr={stderr}"
    );
    assert!(
        stderr.contains(field) && stderr.contains(range),
        "rejection must name {field} and its valid range {range}; stderr={stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("[effective-config]"),
        "invalid policy must not render a normalized effective config"
    );
}

#[test]
fn ml_weight_out_of_range_is_rejected() {
    assert_policy_rejected(&["--ml-weight", "5.0"], "ml_weight", "0.0 and 1.0");
    assert_policy_rejected(&["--ml-weight=-1.0"], "ml_weight", "0.0 and 1.0");
}

#[test]
fn entropy_threshold_out_of_range_is_rejected() {
    assert_policy_rejected(
        &["--entropy-threshold", "99"],
        "entropy_threshold",
        "0.0 and 8.0",
    );
    assert_policy_rejected(
        &["--entropy-threshold=-5"],
        "entropy_threshold",
        "0.0 and 8.0",
    );
}
