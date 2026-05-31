//! KH-GAP-094: `--search` help must match embedded detector count (894).

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
        "detectors --search help must not claim 888 detectors when embedded corpus is 894; help={help}"
    );
    assert!(
        help.contains("894-strong"),
        "detectors --search help must cite 894-strong corpus; help={help}"
    );
}
