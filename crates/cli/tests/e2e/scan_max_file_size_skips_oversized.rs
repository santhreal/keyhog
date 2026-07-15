//! E2E: `--max-file-size` skips files above the threshold.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[path = "../support/json_report.rs"]
mod json_report_support;

use json_report_support::parse_json_array;

#[test]
fn scan_max_file_size_skips_oversized_file() {
    let dir = TempDir::new().expect("tempdir");
    // A scannable small file PLUS an oversized one: the cap skips only the
    // large file, so the scan exercises the PARTIAL-coverage path (scanned
    // some, skipped one): `[]` findings on stdout + an "input coverage was
    // incomplete" gap on stderr. (A dir whose ONLY file is skipped instead
    // hits the stronger "source produced no data" fail-closed, which this test
    // is not about.)
    std::fs::write(dir.path().join("small.txt"), "hello world\n").unwrap();
    std::fs::write(
        dir.path().join("large.txt"),
        "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--format",
            "json",
            // 20 bytes: above `small.txt` (12 B, scanned) and below
            // `large.txt` (43 B, skipped as oversized).
            "--max-file-size",
            "20B",
            "--path",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn");

    assert_eq!(
        output.status.code(),
        Some(13),
        "oversized file must make input coverage incomplete (exit 13); stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains('\x1b'),
        "non-progress mode should not emit ANSI escapes; got: {}",
        stderr
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings = parse_json_array(&stdout, "max-file-size skipped scan JSON");
    assert!(
        findings.is_empty(),
        "skipped file must not produce findings; got: {}",
        stdout
    );
    assert!(
        stderr.contains("input coverage was incomplete")
            && stderr.contains("exceeded --max-file-size"),
        "oversized clean-looking scan must explain the incomplete coverage; stderr={stderr}"
    );
}

#[test]
fn csv_zero_finding_partial_scan_has_status_preamble() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("small.txt"), "hello world\n").unwrap();
    std::fs::write(
        dir.path().join("large.txt"),
        "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--format",
            "csv",
            "--max-file-size",
            "20B",
            "--path",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn keyhog");

    assert_eq!(output.status.code(), Some(13));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    let preamble = lines
        .next()
        .expect("CSV must begin with scan metadata preamble");
    let metadata: serde_json::Value = serde_json::from_str(
        preamble
            .strip_prefix("# keyhog.scan.metadata=")
            .expect("CSV metadata prefix"),
    )
    .expect("CSV metadata JSON");
    assert_eq!(metadata["scan_status"], "partial");
    assert!(!metadata["coverage_gap_summary"]
        .as_array()
        .expect("coverage gap summary array")
        .is_empty());
    assert!(
        lines
            .next()
            .is_some_and(|line| line.starts_with("detector_id,")),
        "CSV metadata must be followed by the canonical header"
    );
    assert!(
        lines.next().is_none(),
        "zero-finding partial scan must not emit a data row"
    );
}
