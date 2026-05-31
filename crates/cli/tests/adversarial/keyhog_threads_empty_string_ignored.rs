//! Adversarial: empty KEYHOG_THREADS must not crash.

use crate::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn keyhog_threads_empty_string_ignored() {
    let (_dir, path) = write_temp_file("clean.txt", "ok\n");
    let output = Command::new(binary())
        .env("KEYHOG_THREADS", "")
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
}
