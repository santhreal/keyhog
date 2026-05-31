//! Adversarial: KEYHOG_DETECTORS pointing at missing dir falls back safely.

use crate::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn keyhog_detectors_missing_path_ignored() {
    let (_dir, path) = write_temp_file("clean.txt", "ok\n");
    let output = Command::new(binary())
        .env(
            "KEYHOG_DETECTORS",
            "/nonexistent/keyhog-detectors-adversarial",
        )
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
}
