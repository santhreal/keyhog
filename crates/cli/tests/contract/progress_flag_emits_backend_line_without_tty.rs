//! Contract: `--progress` must emit progress UI even when stderr is piped.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn progress_flag_emits_backend_line_without_tty() {
    let (_dir, path) = write_temp_file("clean.txt", "hello\n");
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--progress", "--format", "json"])
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("backend=") || stderr.contains("Scan complete"),
        "--progress must surface scan progress on stderr when not a TTY; got: {stderr}"
    );
}
