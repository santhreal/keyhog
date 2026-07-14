use keyhog::testing::{CliTestApi, API};
use keyhog_core::VerificationResult;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn removed_credentials_use_conclusive_typed_states_only() {
    assert_eq!(
        API.removed_verification_state(&VerificationResult::Live),
        "removed_still_live"
    );
    assert!(API.removed_verification_blocks_success(&VerificationResult::Live));
    for result in [VerificationResult::Dead, VerificationResult::Revoked] {
        assert_eq!(API.removed_verification_state(&result), "removed_inactive");
        assert!(!API.removed_verification_blocks_success(&result));
    }
}

#[test]
fn incomplete_verification_never_becomes_inactive() {
    let incomplete = [
        VerificationResult::RateLimited,
        VerificationResult::Error("credential-shaped-value-must-not-escape".into()),
        VerificationResult::Unverifiable,
        VerificationResult::Skipped,
    ];
    for result in incomplete {
        assert_eq!(
            API.removed_verification_state(&result),
            "verification_unknown"
        );
        assert!(API.removed_verification_blocks_success(&result));
    }
}

#[test]
fn artifact_removal_is_scanned_redacted_and_unknown_without_verification() {
    const CREDENTIAL: &str = "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";
    let dir = TempDir::new().expect("tempdir");
    let before = dir.path().join("before.env");
    let after = dir.path().join("after.env");
    std::fs::write(&before, format!("GH_TOKEN={CREDENTIAL}\n")).expect("write before");
    std::fs::write(&after, "GH_TOKEN=rotated-out-of-source\n").expect("write after");

    let output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args(["diff", "--artifacts", "--json"])
        .arg(&before)
        .arg(&after)
        .output()
        .expect("run artifact diff");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(!stdout.contains(CREDENTIAL), "stdout leaked the credential");
    assert!(!stderr.contains(CREDENTIAL), "stderr leaked the credential");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("json report");
    assert_eq!(
        report["removed"][0]["state"].as_str(),
        Some("verification_unknown")
    );
    assert_eq!(
        report["summary"]["verification_unknown_count"].as_u64(),
        Some(1),
        "cross-detector aliases must collapse before removal classification"
    );
}

#[test]
fn artifact_only_tuning_is_rejected_for_baseline_comparison() {
    let output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args([
            "diff",
            "before.json",
            "after.json",
            "--max-artifact-bytes",
            "1024",
        ])
        .output()
        .expect("run invalid baseline diff");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("--artifacts"), "{stderr}");
}

#[test]
fn verification_timeout_requires_removed_verification() {
    let output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args([
            "diff",
            "--artifacts",
            "before.env",
            "after.env",
            "--verify-timeout",
            "1",
        ])
        .output()
        .expect("run invalid artifact diff");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("--verify-removed"), "{stderr}");
}

#[test]
fn zero_artifact_read_cap_fails_before_scanning() {
    let dir = TempDir::new().expect("tempdir");
    let before = dir.path().join("before.env");
    let after = dir.path().join("after.env");
    std::fs::write(&before, "VALUE=before\n").expect("write before");
    std::fs::write(&after, "VALUE=after\n").expect("write after");

    let output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args(["diff", "--artifacts", "--max-artifact-bytes", "0"])
        .arg(&before)
        .arg(&after)
        .output()
        .expect("run zero-cap artifact diff");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("must be greater than zero"), "{stderr}");
}

#[test]
#[cfg(not(feature = "verify"))]
fn unavailable_verifier_fails_even_when_no_credential_was_removed() {
    let dir = TempDir::new().expect("tempdir");
    let detectors = dir.path().join("detectors");
    std::fs::create_dir(&detectors).expect("detector dir");
    std::fs::write(
        detectors.join("minimal.toml"),
        r#"
[detector]
id = "minimal-test"
name = "Minimal test"
service = "minimal-test"
severity = "high"
keywords = ["khv_"]

[[detector.patterns]]
regex = 'khv_[A-Za-z0-9]{20}'
"#,
    )
    .expect("write detector");
    let before = dir.path().join("before.env");
    let after = dir.path().join("after.env");
    std::fs::write(&before, "NO_SECRET=present\n").expect("write before");
    std::fs::write(&after, "NO_SECRET=present\n").expect("write after");

    let output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args(["diff", "--artifacts", "--verify-removed", "--detectors"])
        .arg(&detectors)
        .arg(&before)
        .arg(&after)
        .output()
        .expect("run unavailable verifier");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("requires a keyhog build"), "{stderr}");
}

#[test]
#[cfg(feature = "verify")]
fn verifier_failure_stays_unknown_in_operator_report() {
    const CREDENTIAL: &str = "khv_A1b2C3d4E5f6G7h8I9j0";
    let dir = TempDir::new().expect("tempdir");
    let detectors = dir.path().join("detectors");
    std::fs::create_dir(&detectors).expect("detector dir");
    std::fs::write(
        detectors.join("removed-verifier.toml"),
        r#"
[detector]
id = "removed-verifier-test"
name = "Removed verifier test"
service = "removed-verifier-test"
severity = "high"
keywords = ["khv_"]

[[detector.patterns]]
regex = 'khv_[A-Za-z0-9]{20}'

[detector.verify]
method = "GET"
url = "https://127.0.0.1/credential-check"
allowed_domains = ["127.0.0.1"]

[detector.verify.auth]
type = "bearer"
field = "match"

[detector.verify.success]
status = 200
"#,
    )
    .expect("write detector");
    let before = dir.path().join("before.env");
    let after = dir.path().join("after.env");
    std::fs::write(&before, format!("REMOVED_TOKEN={CREDENTIAL}\n")).expect("write before");
    std::fs::write(&after, "REMOVED_TOKEN=gone\n").expect("write after");

    let output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args([
            "diff",
            "--artifacts",
            "--verify-removed",
            "--verify-timeout",
            "1",
            "--detectors",
        ])
        .arg(&detectors)
        .arg("--json")
        .arg(&before)
        .arg(&after)
        .output()
        .expect("run verified artifact diff");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(!stdout.contains(CREDENTIAL), "stdout leaked the credential");
    assert!(!stderr.contains(CREDENTIAL), "stderr leaked the credential");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("json report");
    assert_eq!(
        report["removed"][0]["state"].as_str(),
        Some("verification_unknown")
    );
    assert_eq!(
        report["summary"]["removed_inactive_count"].as_u64(),
        Some(0)
    );
}
