//! Staged scans must preserve Git's byte-exact path boundaries.

#![cfg(unix)]

use crate::e2e::support::binary;
use std::os::unix::ffi::OsStringExt;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn staged_secret_in_newline_non_utf8_filename_is_scanned() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    let init = Command::new("git")
        .args(["init", "-q"])
        .current_dir(repo)
        .status()
        .expect("git init");
    assert!(init.success(), "git init failed: {init}");

    let filename = std::ffi::OsString::from_vec(b"staged-\xff\nsecret.env".to_vec());
    std::fs::write(
        repo.join(&filename),
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n",
    )
    .expect("write hostile-name staged fixture");
    let add = Command::new("git")
        .arg("add")
        .arg(&filename)
        .current_dir(repo)
        .status()
        .expect("git add hostile filename");
    assert!(add.success(), "git add failed: {add}");

    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--git-staged",
            "--format",
            "json",
            "--no-suppress-test-fixtures",
        ])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("spawn staged scan");

    assert_eq!(
        output.status.code(),
        Some(1),
        "staged secret must exit 1; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be JSON");
    let findings = findings.as_array().expect("JSON report must be an array");
    assert_eq!(
        findings.len(),
        1,
        "expected one staged finding: {findings:?}"
    );
    assert_eq!(findings[0]["detector_id"].as_str(), Some("aws-access-key"));
}

#[test]
fn staged_rename_scans_the_destination_blob() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(repo)
        .status()
        .expect("git init")
        .success());
    for (key, value) in [("user.email", "staged@test"), ("user.name", "Staged Test")] {
        assert!(Command::new("git")
            .args(["config", key, value])
            .current_dir(repo)
            .status()
            .expect("git config")
            .success());
    }
    std::fs::write(
        repo.join("original.env"),
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n",
    )
    .expect("write original");
    assert!(Command::new("git")
        .args(["add", "original.env"])
        .current_dir(repo)
        .status()
        .expect("git add")
        .success());
    assert!(Command::new("git")
        .args(["commit", "-qm", "base"])
        .current_dir(repo)
        .status()
        .expect("git commit")
        .success());
    assert!(Command::new("git")
        .args(["mv", "original.env", "renamed.env"])
        .current_dir(repo)
        .status()
        .expect("git mv")
        .success());

    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--git-staged",
            "--format",
            "json",
            "--no-suppress-test-fixtures",
        ])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("spawn staged rename scan");

    assert_eq!(
        output.status.code(),
        Some(1),
        "renamed staged blob must be scanned; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be JSON");
    let finding = &findings.as_array().expect("JSON report must be an array")[0];
    assert_eq!(finding["detector_id"].as_str(), Some("aws-access-key"));
    assert_eq!(
        finding["location"]["file_path"].as_str(),
        Some("renamed.env")
    );
}
