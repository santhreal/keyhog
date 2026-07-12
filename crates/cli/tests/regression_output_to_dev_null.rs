//! Regression (dogfood): `--output /dev/null` must succeed.
//!
//! The report writer replaces its target atomically by creating a sibling temp
//! file in the target's parent directory and renaming it into place. For a
//! character device such as `/dev/null` that parent is `/dev`, which is not
//! writable, so the temp step failed with a confusing
//! `error: atomically writing report /dev/null: Permission denied (.../dev/.tmpXXXX)`
//! and the whole run exited non-zero EVEN THOUGH the scan itself succeeded.
//!
//! `-o /dev/null` is a canonical "discard the report, I only care about the exit
//! code / the stderr stream" sink (benchmarking, CI gating, quick checks), so it
//! must work. The writer now detects a non-regular target and writes straight
//! through to the device instead of staging a temp+rename.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A planted GitHub classic PAT with a valid CRC32 tail (the canonical token
/// from the format/backend parity e2e). It fires `github-classic-pat`, so the
/// run finds exactly one credential and exits with the findings code.
const PLANTED: &str = "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";

#[test]
fn scan_output_to_dev_null_succeeds_and_reports_findings_exit_code() {
    let dir = TempDir::new().expect("tempdir");
    let leak = dir.path().join("leak.env");
    std::fs::write(&leak, format!("GITHUB_TOKEN={PLANTED}\n")).expect("write fixture");

    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--format",
            "json",
        ])
        .args(["--output", "/dev/null"])
        .arg(&leak)
        .env("KEYHOG_NO_GPU", "1")
        .output()
        .expect("spawn keyhog scan");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // The pre-fix failure mode: the atomic temp+rename could not create
    // `/dev/.tmpXXXX`, so reporting aborted. Neither error string may appear.
    assert!(
        !stderr.contains("atomically writing report") && !stderr.contains("Permission denied"),
        "writing the report to /dev/null must not fail with an atomic-rename error; \
         stderr was:\n{stderr}"
    );

    // The scan found one planted credential; with the report written (discarded)
    // to /dev/null, the process exits with the findings code (1), NOT the
    // report-write failure code (2).
    assert_eq!(
        output.status.code(),
        Some(1),
        "scan with a planted secret and `-o /dev/null` must exit 1 (findings \
         found, report discarded), not the write-error code 2; stderr:\n{stderr}"
    );
}
