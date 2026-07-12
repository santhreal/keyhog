//! Contract: the scan completion summary surfaces WHICH backend selection used
//! (the "is GPU backend selection working?" transparency line).
//!
//! The per-batch routing decision used to be logged only at `tracing::debug!`,
//! invisible at default verbosity, so a scan that correctly chose SIMD on a
//! small-file tree read as "backend selection is broken." This test forces SIMD
//! explicitly so the routing line is deterministic and does not depend on a
//! persisted autoroute calibration cache.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn progress_flag_emits_routing_decision_summary() {
    let (_dir, path) = write_temp_file("clean.txt", "hello world, no secrets here\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--progress",
            "--format",
            "json",
            "--backend",
            "simd",
        ])
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("INFO backend:"),
        "completion summary must surface the routing decision line; got: {stderr}"
    );
    assert!(
        stderr.contains("backend: simd-regex"),
        "an explicit SIMD scan must report simd-regex routing on every host; got: {stderr}"
    );
    assert!(
        stderr.contains("forced via --backend"),
        "an explicit backend override must be visible in the routing line; got: {stderr}"
    );
}
