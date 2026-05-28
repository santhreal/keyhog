//! Adversarial: absurd KEYHOG_THREADS must clamp, not fail.

use crate::adversarial::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn keyhog_threads_overflow_clamped() {
    let (_dir, path) = write_temp_file("clean.txt", "ok\n");
    let output = Command::new(binary())
        .env("KEYHOG_THREADS", "9999999")
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
}
