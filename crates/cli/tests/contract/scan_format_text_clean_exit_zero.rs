//! Contract: `--format text` on a clean file exits 0.

use crate::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_text_clean_exit_zero() {
    let (_dir, path) = write_temp_file("clean.txt", "hello world\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "text",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
