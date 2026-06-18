//! Adversarial: KEYHOG_THREADS=0 must warn and keep a safe default.

use crate::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn keyhog_threads_zero_warns() {
    let (_dir, path) = write_temp_file("clean.txt", "ok\n");
    let output = Command::new(binary())
        .env("KEYHOG_THREADS", "0")
        .args(["scan", "--backend", "simd", "--no-daemon", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert!(
        stderr.contains("invalid KEYHOG_THREADS=\"0\"")
            && stderr.contains("expected an integer >= 1")
            && stderr.contains("using"),
        "zero KEYHOG_THREADS must be operator-visible; stderr={stderr}"
    );
}
