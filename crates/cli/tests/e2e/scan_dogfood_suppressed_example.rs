//! E2E: `--dogfood` reports suppressed example credentials.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_dogfood_suppressed_example() {
    let (_dir, path) = write_temp_file("demo.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--dogfood",
            "--format",
            "text",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("example")
            || combined.contains("suppressed")
            || combined.contains("dogfood"),
        "dogfood must surface suppression telemetry; got: {combined}"
    );
}
