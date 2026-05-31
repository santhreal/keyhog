//! Adversarial: KEYHOG_BACKEND env is honored during scan dispatch.

use crate::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn keyhog_backend_env_with_scan() {
    let (_dir, path) = write_temp_file("clean.txt", "ok\n");
    let output = Command::new(binary())
        .env("KEYHOG_BACKEND", "cpu")
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
}
