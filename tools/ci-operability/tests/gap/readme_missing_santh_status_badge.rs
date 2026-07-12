//! KH-GAP-111: STANDARD README contract requires cargo-rdme status badge on every crate README.

use super::support::spec_waiver::spec_waiver_active;
use super::support::{repo_root, CARGO_RDME_WAIVER as WAIVER_REL};

const CRATE_READMES: [&str; 5] = [
    "crates/core/README.md",
    "crates/scanner/README.md",
    "crates/verifier/README.md",
    "crates/sources/README.md",
    "crates/cli/README.md",
];

#[test]
fn workspace_crate_readmes_expose_santh_status_badge() {
    if spec_waiver_active(WAIVER_REL) {
        return;
    }
    for rel in CRATE_READMES {
        let text = std::fs::read_to_string(repo_root().join(rel))
            .unwrap_or_else(|e| panic!("read {rel}: {e}"));
        assert!(
            text.contains("shields.io/badge/santh-"),
            "{rel} must include generated santh status badge per STANDARD.md README contract"
        );
    }
}
