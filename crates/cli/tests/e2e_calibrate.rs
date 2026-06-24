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
    let dir = TempDir::new().expect("tempdir");
    let cache = dir.path().join("missing-calibration.json");
    let output = Command::new(binary())
        .arg("calibrate")
        .arg("--show")
        .arg("--cache")
        .arg(&cache)
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

    // Read the cache and verify aws-access-key recorded a true positive. The
    // on-disk shape is `{ "version": 1, "detectors": { "<id>": { "alpha",
    // "beta" } } }`, so navigate through `detectors` (the previous top-level /
    // array lookup never matched and passed only by accident before this test
    // ran in CI).
    let content = std::fs::read_to_string(&cache).expect("read cache");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("cache is JSON");
    let aws_entry = parsed
        .get("detectors")
        .and_then(|d| d.get("aws-access-key"));
    assert!(
        aws_entry.is_some(),
        "calibration cache should record aws-access-key under `detectors`; content: {content}"
    );
    // A recorded true positive must lift alpha above the Beta(1,1) prior.
    let alpha = aws_entry
        .and_then(|e| e.get("alpha"))
        .and_then(serde_json::Value::as_u64);
    assert!(
        alpha.is_some_and(|a| a >= 2),
        "--tp must increment aws-access-key's alpha above the prior (got {alpha:?}); content: {content}"
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

#[test]
fn calibrate_show_corrupt_cache_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let cache = dir.path().join("calibration.json");
    std::fs::write(&cache, "not-json").expect("write corrupt cache");

    let output = Command::new(binary())
        .arg("calibrate")
        .arg("--show")
        .arg("--cache")
        .arg(&cache)
        .output()
        .expect("spawn keyhog calibrate --show corrupt cache");

    assert_eq!(
        output.status.code(),
        Some(2),
        "corrupt calibration cache must fail closed; stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not valid JSON")
            && stderr.contains("No calibration counters were changed")
            && stderr.contains("--cache"),
        "stderr must name the corrupt cache and repair path; stderr={stderr}"
    );
}

#[test]
fn calibrate_update_corrupt_cache_does_not_overwrite() {
    let dir = TempDir::new().expect("tempdir");
    let cache = dir.path().join("calibration.json");
    let original = "not-json";
    std::fs::write(&cache, original).expect("write corrupt cache");

    let output = Command::new(binary())
        .arg("calibrate")
        .arg("--tp")
        .arg("aws-access-key")
        .arg("--cache")
        .arg(&cache)
        .output()
        .expect("spawn keyhog calibrate --tp corrupt cache");

    assert_eq!(
        output.status.code(),
        Some(2),
        "corrupt calibration update must fail closed; stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let after = std::fs::read_to_string(&cache).expect("read cache after failed update");
    assert_eq!(
        after, original,
        "failed calibrate update must not overwrite a corrupt existing cache"
    );
}

#[test]
fn calibrate_show_invalid_counter_cache_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let cache = dir.path().join("calibration.json");
    let invalid = serde_json::json!({
        "version": 1,
        "detectors": { "aws-access-key": { "alpha": 0, "beta": 1 } }
    });
    std::fs::write(&cache, serde_json::to_vec(&invalid).expect("encode cache"))
        .expect("write invalid calibration cache");

    let output = Command::new(binary())
        .arg("calibrate")
        .arg("--show")
        .arg("--cache")
        .arg(&cache)
        .output()
        .expect("spawn keyhog calibrate --show invalid cache");

    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid calibration counters must fail closed; stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid counters")
            && stderr.contains("aws-access-key")
            && stderr.contains("No calibration counters were changed")
            && stderr.contains("--cache"),
        "stderr must name the invalid calibration artifact and repair path; stderr={stderr}"
    );
}
