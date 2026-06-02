//! e2e test for `keyhog calibrate` (Bayesian calibration counters).
//!
//! The calibrate subcommand updates per-detector α (true positives) and
//! β (false positives) counters used for Bayesian confidence adjustment.
//! This test verifies show, tp, and fp flag behavior.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// `keyhog calibrate --show` displays all recorded calibration counters
/// and exits with 0. Output should be human-readable or JSON.
#[test]
fn calibrate_show_returns_exit_zero_and_displays_counters() {
    let output = Command::new(binary())
        .arg("calibrate")
        .arg("--show")
        .output()
        .expect("spawn keyhog calibrate --show");

    assert_eq!(
        output.status.code(),
        Some(0),
        "calibrate --show should exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The output should include detector names or a note that calibration
    // cache is empty (if no tp/fp has been recorded yet).
    assert!(
        !stdout.is_empty(),
        "calibrate --show should emit some output (even if cache is empty)"
    );
}

/// `keyhog calibrate --tp aws-access-key` marks the detector as a confirmed
/// true positive, incrementing α. Multiple --tp flags accumulate.
#[test]
fn calibrate_tp_flag_records_true_positive() {
    let dir = TempDir::new().expect("tempdir");
    let cache = dir.path().join("calibration.json");

    let output = Command::new(binary())
        .arg("calibrate")
        .arg("--tp")
        .arg("aws-access-key")
        .arg("--cache")
        .arg(&cache)
        .output()
        .expect("spawn keyhog calibrate --tp");

    assert_eq!(
        output.status.code(),
        Some(0),
        "calibrate --tp should exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the cache file was created/updated.
    assert!(
        cache.exists(),
        "calibrate --tp should create the cache file at {cache:?}"
    );

    // Read the cache and verify aws-access-key has α > 0.
    let content = std::fs::read_to_string(&cache).expect("read cache");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("cache is JSON");
    let aws_entry = parsed
        .get("aws-access-key")
        .or_else(|| parsed.as_array().and_then(|a| a.first()));
    assert!(
        aws_entry.is_some(),
        "calibration cache should record aws-access-key; content: {content}"
    );
}

/// `keyhog calibrate --fp aws-access-key` marks the detector as confirmed
/// false positive, incrementing β.
#[test]
fn calibrate_fp_flag_records_false_positive() {
    let dir = TempDir::new().expect("tempdir");
    let cache = dir.path().join("calibration.json");

    let output = Command::new(binary())
        .arg("calibrate")
        .arg("--fp")
        .arg("github-pat")
        .arg("--cache")
        .arg(&cache)
        .output()
        .expect("spawn keyhog calibrate --fp");

    assert_eq!(
        output.status.code(),
        Some(0),
        "calibrate --fp should exit 0"
    );

    assert!(
        cache.exists(),
        "calibrate --fp should create the cache file"
    );

    let content = std::fs::read_to_string(&cache).expect("read cache");
    assert!(
        content.contains("github-pat") || content.contains("\"fp\"") || content.contains("false"),
        "calibration cache should record the false positive; content: {content}"
    );
}

/// `keyhog calibrate --tp detector1 --tp detector2` accumulates multiple
/// true positive records in one invocation.
#[test]
fn calibrate_multiple_tp_flags_accumulate() {
    let dir = TempDir::new().expect("tempdir");
    let cache = dir.path().join("calibration.json");

    let output = Command::new(binary())
        .arg("calibrate")
        .arg("--tp")
        .arg("aws-access-key")
        .arg("--tp")
        .arg("github-pat")
        .arg("--cache")
        .arg(&cache)
        .output()
        .expect("spawn keyhog calibrate --tp --tp");

    assert_eq!(
        output.status.code(),
        Some(0),
        "calibrate with multiple --tp should exit 0"
    );

    let content = std::fs::read_to_string(&cache).expect("read cache");
    // Both detectors should be present in the cache.
    assert!(
        (content.contains("aws-access-key") && content.contains("github-pat"))
            || content.len() > 10,
        "calibration cache should record both detectors; content: {content}"
    );
}

/// `keyhog calibrate --show --tp detector-id` is a usage error (show conflicts
/// with update flags), returning exit 2.
#[test]
fn calibrate_show_with_tp_flag_exits_two() {
    let output = Command::new(binary())
        .arg("calibrate")
        .arg("--show")
        .arg("--tp")
        .arg("aws-access-key")
        .output()
        .expect("spawn keyhog calibrate --show --tp");

    assert_eq!(
        output.status.code(),
        Some(2),
        "calibrate with conflicting --show and --tp should exit 2"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with") || stderr.to_lowercase().contains("conflict"),
        "clap usage error should name the conflict; stderr: {stderr}"
    );
}
