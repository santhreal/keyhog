//! Adversarial: scan-system with unreadable detectors dir exits non-zero.

use crate::support::binary;
use std::process::Command;

#[test]
fn scan_system_missing_detectors_dir_hostile() {
    let output = Command::new(binary())
        .args([
            "scan-system",
            "--space",
            "1M",
            "--detectors",
            "/nonexistent/keyhog-scan-system-detectors",
        ])
        .output()
        .expect("spawn scan-system");
    assert_ne!(output.status.code(), Some(0));
    let combined = format!(
        "{}
{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("detector") || combined.contains("No such file"),
        "missing detectors dir must fail loudly; got: {combined}"
    );
}
