//! Contract: the scan completion summary surfaces WHICH backend the autorouter
//! used (the "is the GPU autorouting working?" transparency line).
//!
//! The per-batch routing decision used to be logged only at `tracing::debug!`,
//! invisible at default verbosity, so a scan that correctly chose SIMD on a
//! small-file tree read as "the autorouting is broken." A tiny single-file scan
//! is ALWAYS routed to SIMD (it never clears the GPU per-dispatch floor), on
//! every host regardless of whether a GPU is present — so the routing line must
//! name `simd-regex` here, deterministically and machine-independently.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn progress_flag_emits_routing_decision_summary() {
    let (_dir, path) = write_temp_file("clean.txt", "hello world, no secrets here\n");
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--progress", "--format", "json"])
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("⚙ backend:"),
        "completion summary must surface the routing decision line; got: {stderr}"
    );
    // A one-chunk scan can never clear the GPU per-dispatch floor, so it routes
    // to SIMD on every host — GPU box or not. The line must say so.
    assert!(
        stderr.contains("backend: simd-regex"),
        "a tiny single-file scan must report simd-regex routing on every host; got: {stderr}"
    );
    // It must point the operator at the routing matrix tool so the WHY is
    // discoverable (closes the "autorouting is broken?" confusion).
    assert!(
        stderr.contains("`keyhog backend`") || stderr.contains("no GPU available"),
        "the SIMD routing line must explain itself (GPU-present rationale + \
         `keyhog backend` pointer, or the no-GPU note); got: {stderr}"
    );
}
