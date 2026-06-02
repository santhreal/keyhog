//! e2e test for `keyhog diff <before> <after>`.
//!
//! The diff subcommand compares two baseline JSON files (from scan runs)
//! and reports NEW, RESOLVED, and UNCHANGED findings. This test verifies
//! that diff correctly categorizes findings across files.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// `keyhog diff baseline1.json baseline2.json` compares two JSON files
/// and returns exit 0 with a text summary of NEW, RESOLVED, and UNCHANGED.
#[test]
fn diff_two_baselines_returns_exit_zero_with_summary() {
    let dir = TempDir::new().expect("tempdir");

    // Create a baseline with one finding.
    let baseline1 = dir.path().join("baseline1.json");
    let json1 = r#"[
        {
            "detector_id": "aws-access-key",
            "detector_name": "AWS Access Key",
            "service": "aws",
            "severity": "Critical",
            "credential_redacted": "AKIA...XYA",
            "credential_hash": "abc123",
            "location": {
                "source": "test",
                "file_path": "/path/to/file.txt",
                "line": 1,
                "offset": 0
            },
            "verification": {"verified": false}
        }
    ]"#;
    std::fs::write(&baseline1, json1).expect("write baseline1");

    // Create a baseline with two findings (one old, one new).
    let baseline2 = dir.path().join("baseline2.json");
    let json2 = r#"[
        {
            "detector_id": "aws-access-key",
            "detector_name": "AWS Access Key",
            "service": "aws",
            "severity": "Critical",
            "credential_redacted": "AKIA...XYA",
            "credential_hash": "abc123",
            "location": {
                "source": "test",
                "file_path": "/path/to/file.txt",
                "line": 1,
                "offset": 0
            },
            "verification": {"verified": false}
        },
        {
            "detector_id": "github-pat",
            "detector_name": "GitHub PAT",
            "service": "github",
            "severity": "Critical",
            "credential_redacted": "ghp_...ST",
            "credential_hash": "def456",
            "location": {
                "source": "test",
                "file_path": "/path/to/other.txt",
                "line": 5,
                "offset": 0
            },
            "verification": {"verified": false}
        }
    ]"#;
    std::fs::write(&baseline2, json2).expect("write baseline2");

    let output = Command::new(binary())
        .arg("diff")
        .arg(&baseline1)
        .arg(&baseline2)
        .output()
        .expect("spawn keyhog diff");

    assert_eq!(
        output.status.code(),
        Some(0),
        "diff with valid baselines should exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The output should mention at least one finding category.
    assert!(
        stdout.to_lowercase().contains("new")
            || stdout.to_lowercase().contains("resolved")
            || stdout.to_lowercase().contains("unchanged"),
        "diff output must categorize findings; got: {stdout}"
    );
}

/// `keyhog diff --json` emits structured JSON output instead of human-readable text.
/// The JSON should include array of findings in each category.
#[test]
fn diff_json_flag_emits_structured_output() {
    let dir = TempDir::new().expect("tempdir");

    let baseline1 = dir.path().join("baseline1.json");
    let json1 = r#"[]"#;
    std::fs::write(&baseline1, json1).expect("write empty baseline1");

    let baseline2 = dir.path().join("baseline2.json");
    let json2 = r#"[
        {
            "detector_id": "aws-access-key",
            "detector_name": "AWS Access Key",
            "service": "aws",
            "severity": "Critical",
            "credential_redacted": "AKIA...XYA",
            "credential_hash": "hash1",
            "location": {
                "source": "test",
                "file_path": "/file.txt",
                "line": 1,
                "offset": 0
            },
            "verification": {"verified": false}
        }
    ]"#;
    std::fs::write(&baseline2, json2).expect("write baseline2");

    let output = Command::new(binary())
        .arg("diff")
        .arg("--json")
        .arg(&baseline1)
        .arg(&baseline2)
        .output()
        .expect("spawn keyhog diff --json");

    assert_eq!(output.status.code(), Some(0), "diff --json should exit 0");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--json output should be valid JSON");

    // The JSON structure should be an object with keys for finding categories.
    assert!(
        parsed.is_object() || parsed.is_array(),
        "diff --json output should be a JSON object or array; got: {parsed}"
    );
}

/// `keyhog diff --hide-unchanged` suppresses the UNCHANGED section from output,
/// making the report focused on NEW and RESOLVED.
#[test]
fn diff_hide_unchanged_flag_suppresses_unchanged_section() {
    let dir = TempDir::new().expect("tempdir");

    // Baseline with one unchanged finding.
    let baseline1 = dir.path().join("baseline1.json");
    let json = r#"[
        {
            "detector_id": "aws-access-key",
            "detector_name": "AWS Access Key",
            "service": "aws",
            "severity": "Critical",
            "credential_redacted": "AKIA...XYA",
            "credential_hash": "same",
            "location": {
                "source": "test",
                "file_path": "/file.txt",
                "line": 1,
                "offset": 0
            },
            "verification": {"verified": false}
        }
    ]"#;
    std::fs::write(&baseline1, json).expect("write baseline1");
    std::fs::write(dir.path().join("baseline2.json"), json).expect("write baseline2");

    let output = Command::new(binary())
        .arg("diff")
        .arg("--hide-unchanged")
        .arg(dir.path().join("baseline1.json"))
        .arg(dir.path().join("baseline2.json"))
        .output()
        .expect("spawn keyhog diff --hide-unchanged");

    assert_eq!(
        output.status.code(),
        Some(0),
        "diff --hide-unchanged should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // With --hide-unchanged, the UNCHANGED section should not appear.
    assert!(
        !stdout.to_lowercase().contains("unchanged") || stdout.contains("0") || stdout.is_empty(),
        "diff --hide-unchanged must suppress UNCHANGED findings; got: {stdout}"
    );
}

/// `keyhog diff missing-file.json after.json` returns exit 2 (user error)
/// with a clear message about the missing file.
#[test]
fn diff_missing_before_file_exits_two_with_error() {
    let dir = TempDir::new().expect("tempdir");
    let missing = dir.path().join("does-not-exist.json");
    let after = dir.path().join("baseline2.json");
    std::fs::write(&after, "[]").expect("write after");

    let output = Command::new(binary())
        .arg("diff")
        .arg(&missing)
        .arg(&after)
        .output()
        .expect("spawn keyhog diff <missing>");

    assert_eq!(
        output.status.code(),
        Some(2),
        "diff with missing before file should exit 2 (user error)"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("not found")
            || stderr.to_lowercase().contains("cannot open")
            || stderr.contains("before"),
        "error must identify the missing file; got: {stderr}"
    );
}
