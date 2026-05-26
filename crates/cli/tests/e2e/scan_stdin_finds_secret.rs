//! E2E: `--stdin` scans piped content.

use crate::e2e::support::binary;
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn scan_stdin_finds_secret() {
    let mut child = Command::new(binary())
        .args(["scan", "--stdin", "--no-daemon", "--format", "json"])
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
    assert!(!arr.is_empty());
}
