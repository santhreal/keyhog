//! E2E (Law 10): scanning a file that matches a structured format but fails to
//! parse must surface the lost decode-through at completion, not swallow it at
//! `tracing::debug!`. A `.yaml` declaring `kind: Secret` with broken YAML is the
//! canonical case — its base64 `data:` values can't be decoded, so any secret
//! encoded inside is invisible unless the operator is told the file didn't parse.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_malformed_k8s_secret_warns_about_lost_decode_through() {
    // Matches the k8s-Secret heuristic (`.yaml` + `kind: Secret`) but the flow
    // sequence is unclosed, so serde_yaml rejects it.
    let (_dir, path) = write_temp_file(
        "secret.yaml",
        "apiVersion: v1\nkind: Secret\ndata:\n  api-key: [unclosed\n",
    );
    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--no-daemon",
            "--progress",
            "--format",
            "json",
        ])
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("matched a structured format") && stderr.contains("FAILED to parse"),
        "a malformed k8s Secret must surface the structured decode-through gap on \
         stderr (Law 10), not swallow it; got: {stderr}"
    );
    assert!(
        stderr.contains("NOT decoded"),
        "the warning must state that encoded secrets were not decoded; got: {stderr}"
    );
}

#[test]
fn scan_malformed_k8s_secret_sarif_reports_lost_decode_through() {
    let (_dir, path) = write_temp_file(
        "secret.yaml",
        "apiVersion: v1\nkind: Secret\ndata:\n  api-key: [unclosed\n",
    );
    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--no-daemon",
            "--format",
            "sarif",
        ])
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn");

    // The malformed Secret's base64 `data:` values can't be decoded, so the
    // scan's structured decode-through coverage is incomplete: it fails closed
    // with exit 13 (incomplete coverage) rather than reporting "clean". The
    // SARIF report is STILL emitted on stdout (raw text was scanned), carrying
    // the toolExecutionNotifications gap asserted below.
    assert_eq!(
        output.status.code(),
        Some(13),
        "malformed k8s Secret raw-text scan must fail closed on incomplete \
         decode-through coverage (exit 13); status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let sarif: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("SARIF stdout must be JSON");
    let notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .expect("scanner structured parse gap must create SARIF notifications");
    assert!(
        notifications.iter().any(|notification| {
            notification["properties"]["reason"].as_str()
                == Some("scanner structured parse failed (raw text scanned; encoded structured values not decoded)")
                && notification["properties"]["count"].as_u64() == Some(1)
        }),
        "SARIF notifications must include the scanner structured parse gap; sarif={sarif}"
    );
}

#[test]
fn scan_valid_k8s_secret_does_not_warn() {
    // Negative twin: a well-formed Secret parses cleanly, so the decode-through
    // gap warning must NOT fire (no false coverage alarm on healthy files).
    let (_dir, path) = write_temp_file(
        "secret.yaml",
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  api-key: YWJjMTIz\n",
    );
    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--no-daemon",
            "--progress",
            "--format",
            "json",
        ])
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("matched a structured format"),
        "a valid k8s Secret must NOT trigger the parse-failure warning; got: {stderr}"
    );
}
