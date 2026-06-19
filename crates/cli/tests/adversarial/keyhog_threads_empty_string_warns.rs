//! Adversarial: retired KEYHOG_THREADS must not affect thread configuration.

use crate::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn keyhog_threads_empty_string_is_ignored() {
    let (_dir, path) = write_temp_file("clean.txt", "ok\n");
    let output = Command::new(binary())
        .env("KEYHOG_THREADS", "")
        .args([
            "scan",
            "--backend",
            "simd",
            "--no-daemon",
            "--format",
            "json",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert!(
        !stderr.contains("KEYHOG_THREADS"),
        "retired KEYHOG_THREADS must be ignored; use --threads or [scan].threads; stderr={stderr}"
    );
}
