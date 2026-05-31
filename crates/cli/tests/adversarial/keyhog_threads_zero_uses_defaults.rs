//! Adversarial: KEYHOG_THREADS=0 must not crash; scan completes.

use crate::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn keyhog_threads_zero_uses_defaults() {
    let (_dir, path) = write_temp_file("clean.txt", "ok\n");
    let output = Command::new(binary())
        .env("KEYHOG_THREADS", "0")
        .args(["scan", "--no-daemon", "--format", "json"])
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
