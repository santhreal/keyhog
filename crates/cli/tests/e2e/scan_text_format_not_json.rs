//! E2E: `--format text` stdout must not start with JSON array.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_text_format_not_json() {
    let (_dir, path) = write_temp_file("planted.txt", "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n");
    let output = Command::new(binary()).args(["scan", "--no-daemon", "--format", "text"]).arg(&path).output().expect("spawn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim_start().starts_with('['), "text format must not leak JSON; got: {stdout}");
}
