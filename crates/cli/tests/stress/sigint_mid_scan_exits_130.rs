//! R5-D2 / KH-GAP-166: SIGINT mid-scan must exit 130 with interrupt message.

use crate::support::{binary, workspace_detectors};
use std::process::{Command, Stdio};
use std::time::Duration;

#[cfg(unix)]
#[test]
fn sigint_mid_scan_exits_130() {
    let child = Command::new(binary())
        // Pin the deterministic CPU-SIMD backend so the scan actually RUNS long
        // enough to be interrupted mid-flight: an un-calibrated `auto` scan
        // fails closed (exit 2) before the 800 ms SIGINT, which would race the
        // signal contract this test exists to verify.
        .args(["scan", "--backend", "simd", "--daemon=off"])
        .arg(workspace_detectors())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn scan");

    std::thread::sleep(Duration::from_millis(800));
    // SAFETY: sending SIGINT to our own child scan process.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }

    let output = child.wait_with_output().expect("wait for interrupted scan");
    assert_eq!(
        output.status.code(),
        Some(130),
        "SIGINT must map to exit 130; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Scan interrupted"),
        "stderr must announce interrupt; got: {stderr}"
    );
}

#[cfg(not(unix))]
#[test]
fn sigint_mid_scan_exits_130() {
    // Windows has no SIGINT contract in STANDARD.md fleet table for this stress slice.
}
