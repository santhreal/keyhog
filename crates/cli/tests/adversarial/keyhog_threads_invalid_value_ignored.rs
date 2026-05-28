//! Adversarial: non-numeric KEYHOG_THREADS must not abort startup.

use crate::adversarial::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn keyhog_threads_invalid_value_ignored() {
    let (_dir, path) = write_temp_file("clean.txt", "ok\n");
    let output = Command::new(binary())
        .env("KEYHOG_THREADS", "not-a-number")
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
}
