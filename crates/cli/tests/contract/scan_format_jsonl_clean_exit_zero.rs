//! Contract: `--format jsonl` on a clean file exits 0.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_jsonl_clean_exit_zero() {
    let (_dir, path) = write_temp_file("clean.txt", "hello world\n");
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "jsonl"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).trim().is_empty());
}
