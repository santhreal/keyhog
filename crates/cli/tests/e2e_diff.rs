//! e2e test for `keyhog diff <before> <after>`.
//!
//! The diff subcommand compares two baseline JSON files (from scan runs)
//! and reports NEW, REMOVED, and UNCHANGED findings. This test verifies
//! that diff correctly categorizes findings across files.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn baseline_json(entries: &str) -> String {
    format!(
        r#"{{
            "version": 1,
            "created": "test",
            "entries": [
                {entries}
            ]
        }}"#
    )
}

fn entry_json(detector_id: &str, credential_hash: &str, file_path: &str, line: usize) -> String {
    format!(
        r#"{{
            "detector_id": "{detector_id}",
            "credential_hash": "{credential_hash}",
            "file_path": "{file_path}",
            "line": {line},
            "status": "acknowledged"
        }}"#
    )
}

/// `keyhog diff baseline1.json baseline2.json` compares two JSON files
/// and exits 1 when NEW entries are present.
#[test]
fn diff_two_baselines_returns_exit_one_with_summary() {
    let dir = TempDir::new().expect("tempdir");

    // Create a baseline with one finding.
    let baseline1 = dir.path().join("baseline1.json");
    let json1 = baseline_json(&entry_json(
        "aws-access-key",
        "abc123",
        "/path/to/file.txt",
        1,
    ));
    std::fs::write(&baseline1, json1).expect("write baseline1");

    // Create a baseline with two findings (one old, one new).
    let baseline2 = dir.path().join("baseline2.json");
    let json2 = baseline_json(&format!(
        "{},{}",
        entry_json("aws-access-key", "abc123", "/path/to/file.txt", 1),
        entry_json("github-pat", "def456", "/path/to/other.txt", 5)
    ));
    std::fs::write(&baseline2, json2).expect("write baseline2");

    let output = Command::new(binary())
        .arg("diff")
        .arg(&baseline1)
        .arg(&baseline2)
        .output()
        .expect("spawn keyhog diff");

    assert_eq!(
        output.status.code(),
        Some(1),
        "diff with a new baseline entry should exit 1; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("keyhog diff") && stdout.contains("1 new") && stdout.contains("0 removed"),
        "diff summary must report exact new and removed counts; got: {stdout}"
    );
    // The output should mention at least one finding category.
    assert!(
        stdout.to_lowercase().contains("new")
            || stdout.to_lowercase().contains("removed")
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
    std::fs::write(&baseline1, baseline_json("")).expect("write empty baseline1");

    let baseline2 = dir.path().join("baseline2.json");
    let json2 = baseline_json(&entry_json("aws-access-key", "hash1", "/file.txt", 1));
    std::fs::write(&baseline2, json2).expect("write baseline2");

    let output = Command::new(binary())
        .arg("diff")
        .arg("--json")
        .arg(&baseline1)
        .arg(&baseline2)
        .output()
        .expect("spawn keyhog diff --json");

    assert_eq!(
        output.status.code(),
        Some(1),
        "diff --json should exit 1 when NEW entries exist"
    );

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
/// making the report focused on NEW and REMOVED.
#[test]
fn diff_hide_unchanged_flag_suppresses_unchanged_section() {
    let dir = TempDir::new().expect("tempdir");

    // Baseline with one unchanged finding.
    let baseline1 = dir.path().join("baseline1.json");
    let json = baseline_json(&entry_json("aws-access-key", "same", "/file.txt", 1));
    std::fs::write(&baseline1, &json).expect("write baseline1");
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
    // With --hide-unchanged, no per-finding UNCHANGED row appears. The summary
    // count remains visible.
    assert!(
        !stdout.lines().any(|line| line.starts_with("UNCHANGED ")),
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
    std::fs::write(&after, baseline_json("")).expect("write after");

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
        stderr.contains("does not exist") && stderr.contains("does-not-exist.json"),
        "error must identify the missing file; got: {stderr}"
    );
}
