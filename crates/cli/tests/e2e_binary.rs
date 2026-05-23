//! End-to-end tests that drive the real `keyhog` binary.
//!
//! Per the per-rule contract (CLAUDE.md test type 10), "the product
//! is the binary." These tests:
//!
//! * use `env!("CARGO_BIN_EXE_keyhog")` — cargo points this at the
//!   freshly built `keyhog` binary in `target/<profile>/keyhog`, so we
//!   exercise the same executable users get;
//! * write a planted-credential fixture to `tempfile::TempDir` (out of
//!   the workspace, so `.gitignore` skip rules don't interfere — keyhog
//!   walks `.internal/` etc. as gitignored, which this test would
//!   otherwise trip);
//! * parse `--format json` stdout, verify shape + counts;
//! * verify the documented exit codes.
//!
//! The fixture is small and self-contained so the test is fast
//! enough to live in the normal `cargo test` flow.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// One-line helper: write a temp file with given content, scan it
/// with `--format json`, return (stdout, stderr, exit-code).
fn scan_text_file(content: &str, extra_args: &[&str]) -> (String, String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.txt");
    std::fs::write(&path, content).expect("write fixture");

    let output = Command::new(binary())
        .arg("scan")
        .args(extra_args)
        .arg("--format")
        .arg("json")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

#[test]
fn scan_finds_planted_aws_key_and_returns_exit_1() {
    let fixture = "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n";
    let (stdout, _stderr, code) = scan_text_file(fixture, &[]);

    // Documented exit codes: 0 = clean, 1 = unverified findings.
    // Planted key with no `--verify` should land us at 1.
    assert_eq!(
        code,
        Some(1),
        "expected exit 1 (unverified findings); got {code:?}"
    );

    let findings: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    let arr = findings.as_array().expect("findings JSON is an array");
    assert!(!arr.is_empty(), "expected at least one finding");
    let aws = arr
        .iter()
        .find(|f| f.get("detector_id").and_then(|v| v.as_str()) == Some("aws-access-key"));
    assert!(
        aws.is_some(),
        "expected aws-access-key finding; got: {arr:?}",
    );
}

#[test]
fn scan_returns_exit_0_on_clean_file() {
    let fixture = "fn main() { println!(\"hello\"); }\n";
    let (stdout, _stderr, code) = scan_text_file(fixture, &[]);

    assert_eq!(code, Some(0), "expected exit 0 on clean file; got {code:?}");
    let findings: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    let arr = findings.as_array().expect("findings JSON is an array");
    assert!(arr.is_empty(), "expected zero findings; got: {arr:?}");
}

#[test]
fn scan_json_schema_carries_required_fields() {
    let fixture = "GH_TOKEN = \"ghp_aBcD1234EFgh5678ijkl9012MNop3456qrST\"\n";
    let (stdout, _stderr, _code) = scan_text_file(fixture, &[]);

    let findings: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    let arr = findings.as_array().expect("findings JSON is an array");
    assert!(!arr.is_empty(), "expected the GH token to fire");

    // Every finding MUST carry the contract fields downstream
    // consumers (CI gates, SARIF converters, IDE plugins) depend on.
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

/// README binding test: the banner advertises an exact detector +
/// pattern count. If we add detectors or rewrite a regex pair, the
/// banner becomes a lie unless updated. This test surfaces drift
/// before it ships.
///
/// README line under audit (root README.md):
///   `KeyHog vX.Y.Z | ... | 888 detectors (1697 patterns)`
///
/// When you legitimately change the counts:
///   1. Update README.md banner.
///   2. Update these two constants.
///   3. CI stays green.
#[test]
fn readme_banner_counts_match_loaded_corpus() {
    const README_DETECTOR_COUNT: usize = 888;
    const README_PATTERN_COUNT: usize = 1697;

    let output = Command::new(binary())
        .arg("detectors")
        .arg("--json")
        .output()
        .expect("spawn keyhog detectors --json");
    assert_eq!(output.status.code(), Some(0));
    let arr: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("detectors JSON parse");
    let actual_patterns: usize = arr
        .iter()
        .map(|d| {
            d.get("patterns")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        })
        .sum();

    assert_eq!(
        arr.len(),
        README_DETECTOR_COUNT,
        "README banner says {README_DETECTOR_COUNT} detectors; actual={}. \
         Update README and the constant in this test together.",
        arr.len(),
    );
    assert_eq!(
        actual_patterns, README_PATTERN_COUNT,
        "README banner says {README_PATTERN_COUNT} patterns; actual={actual_patterns}. \
         Update README and the constant in this test together.",
    );
}

#[test]
fn detectors_subcommand_emits_json_array() {
    let output = Command::new(binary())
        .arg("detectors")
        .arg("--json")
        .output()
        .expect("spawn keyhog detectors --json");
    assert_eq!(
        output.status.code(),
        Some(0),
        "detectors --json should exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("detectors --json stdout is valid JSON");
    let arr = parsed.as_array().expect("--json output is a JSON array");
    assert!(
        arr.len() > 100,
        "expected hundreds of detectors; got {}",
        arr.len()
    );
    // Spot-check one well-known detector.
    let aws = arr
        .iter()
        .find(|d| d.get("id").and_then(|v| v.as_str()) == Some("aws-access-key"));
    assert!(
        aws.is_some(),
        "aws-access-key should appear in --json output"
    );
    let aws = aws.unwrap();
    assert_eq!(
        aws.get("service").and_then(|v| v.as_str()),
        Some("aws"),
        "aws-access-key should have service=aws",
    );
}

/// Tier-B suppression flag: by default keyhog suppresses Stripe's
/// public docs demo key (and other documented test fixtures), so
/// scanning a fixture containing it surfaces 0 findings. Passing
/// `--no-suppress-test-fixtures` flips that — the same fixture
/// produces the finding gitleaks and trufflehog also report.
///
/// This is the binding test for the Tier-B move (task #60). If
/// someone deletes the bundled `test-fixtures.toml` entry for
/// Stripe, the default-mode assertion below catches it; if someone
/// drops the `--no-suppress-test-fixtures` arg, the opt-out branch
/// catches it.
#[test]
fn no_suppress_test_fixtures_surfaces_stripe_demo_key() {
    // The canonical Stripe public-docs demo key. Split via `concat!`
    // so GitHub Push Protection doesn't scan this source file as a
    // live secret leak.
    let stripe_key = concat!("sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dc");
    let fixture = format!("STRIPE_KEY = \"{stripe_key}\"\n");

    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.txt");
    std::fs::write(&path, &fixture).expect("write fixture");

    // ----- default: suppressed -----------------------------------
    let default_out = Command::new(binary())
        .arg("scan")
        .arg("--format")
        .arg("json")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan (default)");
    let default_json = String::from_utf8_lossy(&default_out.stdout);
    let default_findings: serde_json::Value =
        serde_json::from_str(&default_json).expect("default-mode stdout is JSON");
    let default_arr = default_findings.as_array().expect("array");
    let has_stripe = default_arr
        .iter()
        .any(|f| f.get("service").and_then(|v| v.as_str()) == Some("stripe"));
    assert!(
        !has_stripe,
        "default mode MUST suppress the Stripe demo key; got findings: {default_arr:?}"
    );

    // ----- --no-suppress-test-fixtures: surfaced -----------------
    let optout_out = Command::new(binary())
        .arg("scan")
        .arg("--no-suppress-test-fixtures")
        .arg("--format")
        .arg("json")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan (opt-out)");
    let optout_json = String::from_utf8_lossy(&optout_out.stdout);
    let optout_findings: serde_json::Value =
        serde_json::from_str(&optout_json).expect("opt-out stdout is JSON");
    let optout_arr = optout_findings.as_array().expect("array");
    let has_stripe_now = optout_arr
        .iter()
        .any(|f| f.get("service").and_then(|v| v.as_str()) == Some("stripe"));
    assert!(
        has_stripe_now,
        "--no-suppress-test-fixtures MUST surface the Stripe demo key; \
         got findings: {optout_arr:?}"
    );
}

/// Regression for the demo-secret.env UX bug originally flagged
/// in TODO.md (2026-05-17): scanning a file that holds an
/// AWS-published EXAMPLE credential (AKIAIOSFODNN7EXAMPLE) used to
/// print "No secrets found. Your code is clean." — identical to a
/// genuinely clean repo — because the test-fixture suppression
/// filtered the match BEFORE the example-suppression telemetry
/// counter saw it. The reporter then read counter=0 and chose the
/// clean-repo summary.
///
/// v0.5.6 wired `record_example_suppression` for the engine-side
/// EXAMPLE token check, but missed this orchestrator-level
/// test-fixture filter, so the bug came back as soon as the AWS
/// fixture went through the substring suppression instead of the
/// engine path. This test pins the right behaviour:
///
/// * Default mode → output contains "example/test key" and does
///   NOT contain the all-clean summary.
/// * The bundled AWS-EXAMPLE entry must still suppress (no
///   finding shown in the matches list).
#[test]
fn demo_secret_aws_example_summary_distinguishes_suppression_from_clean() {
    let fixture = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("demo-secret.env");
    std::fs::write(&path, fixture).expect("write fixture");

    // --no-daemon to guarantee the in-process orchestrator path is
    // exercised (the daemon path lives in `subcommands/scan.rs` and
    // is locked by `daemon_route_test_fixture_suppression_records_telemetry`
    // below).
    let out = Command::new(binary())
        .arg("scan")
        .arg("--no-daemon")
        .arg("--format")
        .arg("text")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan demo-secret.env");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("example/test key") && stdout.contains("suppressed"),
        "demo-secret.env summary must distinguish suppressed-example from a \
         clean repo. Got stdout: {stdout}"
    );
    assert!(
        !stdout.contains("Your code is clean."),
        "the clean-repo summary must NOT fire when an example credential was \
         suppressed. Got stdout: {stdout}"
    );
}

#[test]
fn explicit_format_text_does_not_emit_json() {
    let fixture = "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n";
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.txt");
    std::fs::write(&path, fixture).expect("write fixture");

    // Don't share the json-format helper here — text-format is the
    // contrast case we're asserting.
    let output = Command::new(binary())
        .arg("scan")
        .arg("--format")
        .arg("text")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan --format text");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    // Text mode is the human-facing default. The hard contract:
    // (1) stdout MUST NOT start with `[` (would mean JSON leaked
    //     through), and (2) the combined stream must reference the
    //     finding somewhere — text reporter writes to stdout or
    //     stderr depending on `--output`; we accept either.
    assert!(
        !stdout.trim_start().starts_with('['),
        "text format must not start with JSON `[`; got: {stdout}",
    );
    assert!(
        combined.to_lowercase().contains("aws") || combined.contains("AKIA"),
        "text format should mention the finding somewhere; \
         stdout={stdout:?}, stderr={stderr:?}, exit={:?}",
        output.status.code(),
    );
}
