//! E2E: `--stdin` scans piped content.

use crate::e2e::support::binary;
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn scan_stdin_finds_secret() {
    let mut child = Command::new(binary())
        .args([
            "scan",
            "--stdin",
            "--daemon=off",
            "--format",
            "json",
            "--backend",
            "simd",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n")
        .unwrap();
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed = serde_json::from_str::<serde_json::Value>(&stdout).expect("json");
    let arr = parsed.as_array().expect("array");
    // Truth, not shape: the piped AWS key must surface as exactly one
    // aws-access-key finding on line 1, redacted first2...last2.
    assert_eq!(arr.len(), 1, "exactly one finding for the planted AWS key");
    let f = &arr[0];
    assert_eq!(f["detector_id"], "aws-access-key");
    assert_eq!(f["service"], "aws");
    assert_eq!(f["severity"], "critical");
    assert_eq!(f["credential_redacted"], "AK...YA");
    assert_eq!(f["location"]["line"], 1);
}
