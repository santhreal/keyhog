//! E2E: suppressed AWS EXAMPLE must not print clean-repo summary.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_demo_example_not_clean_summary() {
    let (_dir, path) = write_temp_file("demo-secret.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
    let output = Command::new(binary()).args(["scan", "--no-daemon", "--format", "text"]).arg(&path).output().expect("spawn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Your code is clean."), "suppressed example must not show clean summary; got: {stdout}");
}
