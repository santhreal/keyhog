//! Adversarial: absurd KEYHOG_THREADS must warn, clamp, and keep running.

use crate::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn keyhog_threads_overflow_clamp_warns() {
    let (_dir, path) = write_temp_file("clean.txt", "ok\n");
    let output = Command::new(binary())
        .env("KEYHOG_THREADS", "9999999")
        .args(["scan", "--backend", "simd", "--no-daemon", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert!(
        stderr.contains("env:KEYHOG_THREADS thread count 9999999 exceeds cap")
            && stderr.contains("using 256"),
        "oversized KEYHOG_THREADS clamp must be operator-visible; stderr={stderr}"
    );
}
