//! R5-D2 / KH-GAP-172: piping stderr must not break JSON stdout contract.

use crate::e2e::support::{binary, write_temp_file};
use std::process::{Command, Stdio};

#[test]
fn piped_stderr_scan_json_stdout_valid() {
    let (_dir, path) = write_temp_file("clean.txt", "hello\n");
    let child = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0));
    let _: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("valid json stdout");
    assert!(
        !output.stderr.is_empty() || output.stdout.starts_with(b"["),
        "stdout must remain machine JSON while stderr carries status"
    );
}
