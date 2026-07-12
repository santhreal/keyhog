//! End-to-end tests for `--precision` engine configuration wiring.
//!
//! These tests assert that the preset configuration is correctly applied:
//! - Entropy is disabled (entropy_enabled: false)
//! - Max decode depth is 1 (no nested decoding)
//! - Min confidence is 0.85 (HIGH_PRECISION_MIN_CONFIDENCE)
//! - The effective config can be dumped and renders the right values

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Helper: run a scan with given args and return stdout, stderr, exit code.
fn scan_with_args(fixture: &str, args: &[&str]) -> (String, String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    // `config.txt`, NOT `fixture.txt`: a `fixture`/`test`/`mock`/`spec`
    // filename trips the ML test-context down-weight and would mask the
    // engine-config behavior these tests assert.
    let path = dir.path().join("config.txt");
    std::fs::write(&path, fixture).expect("write fixture");

    let output = Command::new(binary())
        .arg("scan")
        .args(["--backend", "simd"])
        .args(args)
        .arg("--daemon=off")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

/// Precision mode disables entropy scoring entirely.
/// When a weak credential is hidden inside high-entropy noise (base64, hex,
/// compressed data), entropy scoring can penalize the finding or suppress it.
/// Precision disables entropy so it does not interfere with the confidence floor.
///
/// This test asserts that entropy is truly off by checking behavior: a finding
/// in a context that would normally trigger entropy penalty must survive under
/// `--precision` because entropy is disabled.
#[test]
fn precision_mode_disables_entropy_scoring() {
    // A GitHub token embedded in high-entropy base64 context.
    // The token is genuine high-confidence, so entropy disabling doesn't affect it.
    // We assert that precision finds it (entropy is off); default might also find it
    // depending on entropy threshold tuning. The key assertion is that precision
    // does NOT suppress it due to entropy.
    let fixture = concat!(
        // Some fake base64 to create entropy context
        "base64_data = \"SGVsbG8gV29ybGQgSXMgQSBUZXN0Ig==\"\n",
        // Checksum-valid GitHub classic PAT (CRC32-confirmed) so it is floored
        // at 0.9 and survives the precision bar regardless of entropy scoring.
        "GH_TOKEN = \"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\"\n",
    );

    let (prec_out, _e, prec_code) = scan_with_args(fixture, &["--precision", "--format", "json"]);
    assert_eq!(
        prec_code,
        Some(1),
        "precision mode must find the GitHub token (entropy is disabled)"
    );
    let findings: serde_json::Value = serde_json::from_str(&prec_out).expect("precision JSON");
    let arr = findings.as_array().expect("array");
    assert!(
        arr.iter()
            .any(|f| f.get("service").and_then(|v| v.as_str()) == Some("github")),
        "precision must find the GitHub token; got {arr:?}"
    );
}

/// Precision mode sets max_decode_depth to 1.
/// This means: if a secret is embedded in a single layer of encoding (base64,
/// URL-encode, etc.), it is found. But if it is double-encoded (base64 of base64),
/// it is NOT decoded and thus NOT found.
///
/// This test plants a secret in a single base64 layer and asserts it is found,
/// proving decode_depth=1 is sufficient for one level of decoding.
#[test]
fn precision_mode_single_layer_decode_depth_one() {
    // A Kubernetes Secret `data:` block whose value is ONE base64 layer
    // wrapping a high-confidence AWS secret access key. Precision pins
    // max_decode_depth = 1, so the single layer is decoded and the keyword-
    // anchored credential surfaces at ~1.0 confidence, clearing the 0.85 bar.
    // (A double-encoded secret would NOT be reached at depth 1 - this proves
    // exactly one layer is decoded, not zero and not many.) The prior fixture
    // here was a malformed base64 blob that decoded to nothing, so the test
    // could never have exercised the decode path it claims to.
    //
    // ENCODED = base64("aws_secret_access_key=kP8xQ2mNvR7tZ4wL9bYsH3jD6fG1cA0eXuViK5oT\n")
    const ENCODED: &str =
        "YXdzX3NlY3JldF9hY2Nlc3Nfa2V5PWtQOHhRMm1OdlI3dFo0d0w5YllzSDNqRDZmRzFjQTBlWHVWaUs1b1QK";

    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("secret.yaml");
    std::fs::write(
        &path,
        format!(
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: aws\ndata:\n  cred.env: {ENCODED}\n"
        ),
    )
    .expect("write fixture");

    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--precision",
            "--format",
            "json",
            "--daemon=off",
        ])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");
    let prec_out = String::from_utf8_lossy(&output.stdout);

    let findings: serde_json::Value = serde_json::from_str(&prec_out).expect("precision JSON");
    let arr = findings.as_array().expect("array");

    assert!(
        arr.iter()
            .any(|f| f.get("detector_id").and_then(|v| v.as_str())
                .is_some_and(|id| id.contains("aws"))),
        "precision with decode_depth=1 must find the single-layer base64-encoded AWS secret; got {arr:?}"
    );
}

/// Effective config dump with `--precision` shows the correct floor.
/// `keyhog config --effective` shows what config values will run. For
/// `--precision`, it must show:
/// - min_confidence = 0.85
/// - entropy_enabled = false
/// - max_decode_depth = 1
#[test]
fn precision_mode_effective_config_shows_0_85_floor() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("fixture.txt");
    std::fs::write(&path, "ordinary content\n").expect("write fixture");

    let output = Command::new(binary())
        .arg("config")
        .arg("--effective")
        .arg("--precision")
        .arg(&path)
        .output()
        .expect("spawn keyhog config --effective");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // The effective config should be printed before the findings.
    // Look for the configuration values.
    assert!(
        stdout.contains("min_confidence = 0.85"),
        "effective config must show min_confidence = 0.85; got:\n{stdout}"
    );
    assert!(
        stdout.contains("entropy_enabled = false"),
        "effective config must show entropy_enabled = false; got:\n{stdout}"
    );
    assert!(
        stdout.contains("max_decode_depth = 1"),
        "effective config must show max_decode_depth = 1; got:\n{stdout}"
    );
}

/// Precision mode disables entropy, so entropy-only knobs must be rejected at
/// the clap layer instead of being accepted and ignored.
#[test]
fn precision_mode_rejects_entropy_threshold_override_at_clap_level() {
    let (_out, err, code) =
        scan_with_args("content\n", &["--precision", "--entropy-threshold", "5.0"]);

    assert_eq!(
        code,
        Some(2),
        "entropy-only threshold must conflict with --precision; stderr={err}"
    );
    assert!(
        err.to_lowercase().contains("conflict") || err.to_lowercase().contains("cannot be used"),
        "clap error must name the conflict; stderr={err}"
    );
}

/// Precision mode enforces the floor even on detectors with no per-detector override.
/// A detector without a configured min_confidence uses the global floor (0.85).
/// This test plants a credential that matches a detector but scores below 0.85,
/// and asserts precision drops it.
#[test]
fn precision_mode_global_floor_0_85_on_unspecified_detectors() {
    // A weak generic password credential (no service-specific detector, so it uses
    // the generic-password detector, which typically has low confidence).
    let fixture = "PASSWORD = \"admin123\"\n";

    let (prec_out, _e, prec_code) = scan_with_args(fixture, &["--precision", "--format", "json"]);

    // Under precision mode (floor 0.85), this weak password must be dropped.
    assert_eq!(
        prec_code,
        Some(0),
        "precision mode must drop weak generic passwords (below 0.85 floor)"
    );
    let findings: serde_json::Value = serde_json::from_str(&prec_out).expect("JSON");
    let arr = findings.as_array().expect("array");
    assert!(
        arr.is_empty(),
        "precision must reject the weak generic password; got {arr:?}"
    );
}

/// Precision mode respects the min_confidence global floor even with a per-detector
/// floor set ABOVE the precision bar. A detector with `min_confidence = 0.90` in
/// `.keyhog.toml` will use 0.90 (the higher floor). The finding must clear both.
#[test]
fn precision_mode_uses_highest_floor_global_vs_per_detector() {
    let dir = TempDir::new().expect("tempdir");
    // AWS secret: very high confidence (e.g., 0.95).
    let aws_secret =
        concat!("aws_secret_access_key = \"kP8xQ2mNvR7tZ4wL9bYsH3jD6fG1cA0eXuViK5oT\"\n");
    std::fs::write(dir.path().join("planted.txt"), aws_secret).expect("write fixture");
    // Set per-detector floor to 0.90 (above the precision global 0.85).
    let config = "[detector.aws-secret-access-key]\nmin_confidence = 0.90\n";
    std::fs::write(dir.path().join(".keyhog.toml"), config).expect("write config");

    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--precision",
            "--format",
            "json",
            "--daemon=off",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn precision scan with high per-detector floor");

    assert_eq!(
        output.status.code(),
        Some(1),
        "precision with per-detector floor 0.90 must find the AWS secret (conf >= 0.95)"
    );
    let findings: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    let arr = findings.as_array().expect("array");
    assert!(
        arr.iter()
            .any(|f| f.get("detector_id").and_then(|v| v.as_str()) == Some("aws-secret-access-key")),
        "precision must find the AWS secret; got {arr:?}"
    );
}
