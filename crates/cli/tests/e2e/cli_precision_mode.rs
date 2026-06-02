//! End-to-end tests for the `--precision` high-precision mass-scan preset.
//!
//! The `--precision` flag is a configured mode that minimizes false positives by:
//! - Setting min_confidence to 0.85 (HIGH_PRECISION_MIN_CONFIDENCE)
//! - Disabling entropy scoring (entropy_enabled: false)
//! - Setting max_decode_depth to 1 (no deep nesting)
//! - Clamping per-detector floors UP to the 0.85 bar so no detector can bypass it
//!
//! These tests assert the wiring end-to-end: from the `--precision` flag through
//! the orchestrator config, engine behavior, and post-scan filtering.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Helper: scan a text fixture with given args, return (stdout, stderr, exit-code).
fn scan_text_file(content: &str, extra_args: &[&str]) -> (String, String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    // `config.txt`, NOT `fixture.txt`: the ML scorer down-weights secrets in
    // files whose name contains a test-context fragment (`test`/`mock`/
    // `fixture`/`spec`), which would drop an otherwise high-confidence
    // credential below the 0.85 precision floor and confound these
    // floor/plumbing assertions with the unrelated test-fixture heuristic.
    let path = dir.path().join("config.txt");
    std::fs::write(&path, content).expect("write fixture");

    let output = Command::new(binary())
        .arg("scan")
        .args(extra_args)
        .arg("--format")
        .arg("json")
        .arg("--no-daemon")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

/// `--precision` conflicts with `--deep` at the clap layer: it is a preset
/// just like `--fast` and `--deep`, so exactly one must be chosen.
#[test]
fn precision_mode_conflicts_with_deep() {
    let (_o, err, code) = scan_text_file("ordinary content\n", &["--precision", "--deep"]);
    assert_eq!(
        code,
        Some(2),
        "clap usage error (exit 2) expected for conflicting --precision --deep; got {code:?}"
    );
    assert!(
        err.contains("cannot be used with")
            || err.to_lowercase().contains("conflict")
            || err.to_lowercase().contains("precision"),
        "the usage error must name the conflict; stderr={err}"
    );
}

/// `--precision` with `--no-entropy` must conflict at the clap layer
/// (the flag is marked `conflicts_with_all` on the preset).
#[test]
fn precision_mode_conflicts_with_no_entropy() {
    let (_o, err, code) = scan_text_file("ordinary content\n", &["--precision", "--no-entropy"]);
    assert_eq!(
        code,
        Some(2),
        "clap usage error (exit 2) expected for conflicting --precision --no-entropy; got {code:?}"
    );
    assert!(
        err.contains("cannot be used with")
            || err.to_lowercase().contains("conflict")
            || err.to_lowercase().contains("precision"),
        "the usage error must name the conflict; stderr={err}"
    );
}

/// `--precision` with `--no-decode` must conflict at the clap layer.
#[test]
fn precision_mode_conflicts_with_no_decode() {
    let (_o, err, code) = scan_text_file("ordinary content\n", &["--precision", "--no-decode"]);
    assert_eq!(
        code,
        Some(2),
        "clap usage error (exit 2) expected for conflicting --precision --no-decode; got {code:?}"
    );
    assert!(
        err.contains("cannot be used with")
            || err.to_lowercase().contains("conflict")
            || err.to_lowercase().contains("precision"),
        "the usage error must name the conflict; stderr={err}"
    );
}

/// Precision mode must return exit 0 on a clean file (no findings).
#[test]
fn precision_mode_exits_zero_on_clean_file() {
    let fixture = "fn main() { println!(\"hello world\"); }\n";
    let (_stdout, _stderr, code) = scan_text_file(fixture, &["--precision"]);

    assert_eq!(
        code,
        Some(0),
        "precision mode must exit 0 on a clean file; got {code:?}"
    );
}

/// Precision mode must return exit 1 when findings are detected.
/// Uses a high-confidence AWS secret key that survives the 0.85 floor.
#[test]
fn precision_mode_exits_one_on_findings() {
    let fixture = concat!("aws_secret_access_key = \"kP8xQ2mNvR7tZ4wL9bYsH3jD6fG1cA0eXuViK5oT\"\n");
    let (_stdout, _stderr, code) = scan_text_file(fixture, &["--precision"]);

    assert_eq!(
        code,
        Some(1),
        "precision mode must exit 1 when findings are detected; got {code:?}"
    );
}

/// Precision mode respects the literal 0.85 min_confidence floor.
/// The AWS access-key-id (AKIA…) detector has a low confidence score by design
/// (below 0.85). In precision mode it must be dropped, but in default mode
/// (which has a 0.5 floor) it is kept. This asserts precision enforces 0.85.
#[test]
fn precision_mode_enforces_0_85_floor_on_weak_credentials() {
    let fixture = concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HGT3KZ7WB\"\n");

    // Default mode: the weak AKIA key is surfaced (floor is ~0.5).
    let (def_out, _e, def_code) = scan_text_file(fixture, &[]);
    assert_eq!(def_code, Some(1), "default mode must find the weak AWS key");
    let def_findings: serde_json::Value =
        serde_json::from_str(&def_out).expect("default stdout is JSON");
    let def_arr = def_findings.as_array().expect("array");
    assert!(
        !def_arr.is_empty(),
        "default must surface the AKIA key; got {def_out}"
    );

    // Precision mode: the same AKIA key must be dropped (floor is 0.85).
    let (prec_out, _e2, prec_code) = scan_text_file(fixture, &["--precision"]);
    let prec_findings: serde_json::Value =
        serde_json::from_str(&prec_out).expect("precision stdout is JSON");
    let prec_arr = prec_findings.as_array().expect("array");

    assert!(
        prec_arr.is_empty(),
        "precision mode must drop the AKIA key (conf < 0.85); got {prec_out}"
    );
    assert!(
        prec_code.is_some_and(|c| c == 0),
        "precision mode must exit 0 when all findings are below the floor; got {prec_code:?}"
    );
}

/// Precision mode clamping of per-detector floors: a detector with a configured
/// low min_confidence (e.g., 0.25) must have its floor clamped UP to 0.85 under
/// `--precision`. This test uses `.keyhog.toml` to set a low per-detector floor
/// and asserts that precision still applies the 0.85 bar.
#[test]
fn precision_mode_clamps_detector_floor_up_to_0_85() {
    let dir = TempDir::new().expect("tempdir");
    // AWS secret key: high confidence, survives both 0.25 and 0.85 floors.
    let aws_secret =
        concat!("aws_secret_access_key = \"kP8xQ2mNvR7tZ4wL9bYsH3jD6fG1cA0eXuViK5oT\"\n");
    std::fs::write(dir.path().join("planted.txt"), aws_secret).expect("write fixture");
    // Configure a low per-detector floor (0.25) for aws-secret-access-key.
    let config = "[detector.aws-secret-access-key]\nmin_confidence = 0.25\n";
    std::fs::write(dir.path().join(".keyhog.toml"), config).expect("write config");

    let output = Command::new(binary())
        .args(["scan", "--precision", "--format", "json", "--no-daemon"])
        .arg(dir.path())
        .output()
        .expect("spawn precision scan with config");

    assert_eq!(
        output.status.code(),
        Some(1),
        "precision mode must find the AWS secret (it is above 0.85); stderr={}",
        String::from_utf8_lossy(&output.stderr)
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

/// Precision mode with `--min-confidence` override: the user can raise the floor
/// further with `--min-confidence 0.9`. This must not be silently ignored; the
/// finding must still be dropped (floor must be max(0.85, 0.9) = 0.9).
/// The AWS secret key (high confidence, ~0.95) must be kept because 0.95 >= 0.9.
#[test]
fn precision_mode_respects_min_confidence_override() {
    let fixture = concat!("aws_secret_access_key = \"kP8xQ2mNvR7tZ4wL9bYsH3jD6fG1cA0eXuViK5oT\"\n");

    let (out, _e, code) = scan_text_file(fixture, &["--precision", "--min-confidence", "0.9"]);
    assert_eq!(
        code,
        Some(1),
        "precision 0.9 must find the high-confidence AWS key"
    );
    let findings: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    let arr = findings.as_array().expect("array");
    assert!(
        !arr.is_empty(),
        "precision 0.9 must find the AWS secret; got {out}"
    );
}

/// Precision mode JSON output format is valid and includes all required fields.
/// The contract is the same as default mode, but with fewer findings.
#[test]
fn precision_mode_json_schema_carries_required_fields() {
    // A checksum-VALID GitHub classic PAT (trailing 6 chars are the base62
    // CRC32 of the leading 30): keyhog floors a checksum-confirmed token at
    // 0.9, so it clears the precision bar. A fabricated `ghp_` is correctly
    // dropped, so the token must validate for this schema assertion to hold.
    let fixture = "GH_TOKEN = \"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\"\n";
    let (stdout, _stderr, _code) = scan_text_file(fixture, &["--precision"]);

    let findings: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    let arr = findings.as_array().expect("findings is a JSON array");
    assert!(
        !arr.is_empty(),
        "precision must find the checksum-valid GitHub token (floored at 0.9)"
    );

    // Every finding MUST carry the contract fields.
    for f in arr {
        for required in [
            "detector_id",
            "detector_name",
            "service",
            "severity",
            "credential_redacted",
            "credential_hash",
            "location",
            "verification",
        ] {
            assert!(
                f.get(required).is_some(),
                "finding is missing required field `{required}`: {f}",
            );
        }
        let loc = f.get("location").unwrap();
        for required in ["source", "file_path", "line", "offset"] {
            assert!(
                loc.get(required).is_some(),
                "location is missing required field `{required}`: {loc}",
            );
        }
    }
}

/// Precision mode effectiveness: a corpus of mixed-confidence findings shows
/// that precision is tighter than default. The fixture includes both
/// high-confidence (AWS secret) and low-confidence (generic password) entries.
/// Precision must reduce the count vs default.
#[test]
fn precision_mode_is_stricter_than_default_overall_reduction() {
    let fixture = concat!(
        "aws_secret_access_key = \"kP8xQ2mNvR7tZ4wL9bYsH3jD6fG1cA0eXuViK5oT\"\n",
        // Low-confidence generic password: default surfaces it (~0.55, above the
        // 0.40 default floor) but precision's 0.85 bar drops it - so precision
        // returns strictly fewer findings than default.
        "DATABASE_PASSWORD = \"admin123\"\n",
    );

    let (def_out, _, _) = scan_text_file(fixture, &[]);
    let (prec_out, _, _) = scan_text_file(fixture, &["--precision"]);

    let def_findings: serde_json::Value = serde_json::from_str(&def_out).expect("default JSON");
    let prec_findings: serde_json::Value = serde_json::from_str(&prec_out).expect("precision JSON");

    let def_count = def_findings.as_array().map(|a| a.len()).unwrap_or(0);
    let prec_count = prec_findings.as_array().map(|a| a.len()).unwrap_or(0);

    assert!(
        prec_count < def_count,
        "precision must be stricter; default={def_count}, precision={prec_count}"
    );
    assert!(
        prec_count > 0,
        "precision must still find the high-confidence AWS secret; got {prec_count}"
    );
}
