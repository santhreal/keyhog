//! Adversarial audit: VECTOR 5 (INSUFFICIENCY) + VECTOR 11 (UTILIZATION).
//!
//! These black-box tests drive `keyhog config --effective`. Numeric scanner
//! controls reject values outside their physical domains before config
//! resolution. This fails closed instead of silently clamping an operator typo
//! to a different policy. The scanner sanitiser remains defense in depth for
//! programmatic callers.

use std::path::PathBuf;
use std::process::{Command, Output};

/// Resolve the keyhog binary under test. `CARGO_BIN_EXE_keyhog` is injected by
/// Cargo for integration tests; fall back to the prebuilt release-fast artifact.
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

/// Spawn an invalid `keyhog config --effective` request.
fn invalid_effective_config(extra_args: &[&str], target: &std::path::Path) -> Output {
    let mut args: Vec<String> = vec![
        "config".to_string(),
        "--effective".to_string(),
        "--no-gpu".to_string(),
    ];
    args.extend(extra_args.iter().map(|s| s.to_string()));
    args.push(target.display().to_string());

    Command::new(binary())
        .args(&args)
        .output()
        .expect("spawn keyhog")
}

fn assert_invalid_numeric(output: &Output, field: &str, range: &str) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid {field} must be a user error"
    );
    assert!(
        output.stdout.is_empty(),
        "invalid {field} must not render an effective config"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid value") && stderr.contains(field) && stderr.contains(range),
        "invalid {field} must identify its accepted range; stderr={stderr:?}"
    );
}

/// Create a throwaway scan target inside the test's own temp dir.
fn scratch_file() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("f.txt");
    std::fs::write(&path, b"x = 1\n").expect("write scratch file");
    (dir, path)
}

/// Values above the ML blend domain fail before config resolution.
#[test]
fn ml_weight_above_one_is_rejected() {
    let (_dir, file) = scratch_file();
    let output = invalid_effective_config(&["--ml-weight", "5.0"], &file);
    assert_invalid_numeric(&output, "ml_weight", "between 0.0 and 1.0");
}

/// Negative ML blend weights cannot invert confidence scoring.
#[test]
fn ml_weight_below_zero_is_rejected() {
    let (_dir, file) = scratch_file();
    let output = invalid_effective_config(&["--ml-weight=-1.0"], &file);
    assert_invalid_numeric(&output, "ml_weight", "between 0.0 and 1.0");
}

/// Thresholds above the byte-level Shannon entropy maximum fail closed.
#[test]
fn entropy_threshold_above_max_is_rejected() {
    let (_dir, file) = scratch_file();
    let output = invalid_effective_config(&["--entropy-threshold", "99"], &file);
    assert_invalid_numeric(&output, "entropy_threshold", "between 0.0 and 8.0");
}

/// Negative entropy thresholds cannot turn every byte run into a candidate.
#[test]
fn entropy_threshold_below_zero_is_rejected() {
    let (_dir, file) = scratch_file();
    let output = invalid_effective_config(&["--entropy-threshold=-5"], &file);
    assert_invalid_numeric(&output, "entropy_threshold", "between 0.0 and 8.0");
}
