//! Adversarial: detectors --detectors missing path falls back or errors loudly.

use crate::support::binary;
use std::process::Command;

#[test]
fn detectors_missing_detectors_dir_hostile() {
    let output = Command::new(binary())
        .args([
            "detectors",
            "--detectors",
            "/nonexistent/keyhog-detectors-dir",
        ])
        .output()
        .expect("spawn detectors");
    // Embedded corpus fallback must still list detectors — stdout non-empty JSON array or table.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success()
            && (stdout.contains("aws-access-key") || stdout.contains("detector")),
        "detectors must not silently return empty on bad --detectors; code={:?} stdout={stdout}",
        output.status.code()
    );
}
