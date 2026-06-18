//! Adversarial: non-numeric KEYHOG_THREADS must warn and keep a safe default.

use crate::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn keyhog_threads_invalid_value_warns() {
    let (_dir, path) = write_temp_file("clean.txt", "ok\n");
    let output = Command::new(binary())
        .env("KEYHOG_THREADS", "not-a-number")
        .args(["scan", "--backend", "simd", "--no-daemon", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert!(
        stderr.contains("invalid KEYHOG_THREADS=\"not-a-number\"")
            && stderr.contains("expected an integer >= 1")
            && stderr.contains("using"),
        "invalid KEYHOG_THREADS must be operator-visible; stderr={stderr}"
    );
}
