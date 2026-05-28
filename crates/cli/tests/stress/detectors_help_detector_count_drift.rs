//! KH-GAP-094: `--search` help still says "888-strong corpus" while runtime loads 891.

use crate::e2e::support::binary;
use std::process::Command;

#[test]
fn detectors_search_help_does_not_undercount_embedded_corpus() {
    let output = Command::new(binary())
        .args(["detectors", "--help"])
        .output()
        .expect("spawn");

    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        !help.contains("888-strong"),
        "detectors --search help must not claim 888 detectors when embedded corpus is 891; help={help}"
    );
}

#[test]
fn detectors_listing_reports_at_least_891_loaded() {
    let output = Command::new(binary())
        .args(["detectors"])
        .output()
        .expect("spawn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("891"),
        "detectors banner must reflect current embedded count (891); stdout={stdout}"
    );
}
