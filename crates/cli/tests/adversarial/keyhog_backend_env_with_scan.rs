//! Adversarial: legacy KEYHOG_BACKEND env is ignored during scan dispatch.

use crate::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn legacy_keyhog_backend_env_is_ignored_with_explicit_backend_flag() {
    let (_dir, path) = write_temp_file("clean.txt", "ok\n");
    let output = Command::new(binary())
        .env("KEYHOG_BACKEND", "not-a-real-backend")
        .args([
            "scan",
            "--daemon=off",
            "--format",
            "json",
            "--backend",
            "simd",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
}
