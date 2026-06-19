//! KH-GAP-111: cargo-rdme README SPEC waiver must document owner, reason, and expiry.

#[path = "support/mod.rs"]
mod support;

use support::spec_waiver::{repo_root, spec_waiver_active};

const WAIVER_REL: &str = "tools/ci-operability/spec_waivers/cargo_rdme_readme_contract.toml";

#[test]
fn cargo_rdme_spec_waiver_has_expiry() {
    let waiver = std::fs::read_to_string(repo_root().join(WAIVER_REL)).expect("waiver TOML");
    assert!(
        waiver.contains("gap_id = \"KH-GAP-111\""),
        "waiver must name KH-GAP-111"
    );
    assert!(
        waiver.contains("expires = \""),
        "waiver must declare expires = \"YYYY-MM-DD\""
    );
    assert!(
        waiver.contains("owner = \""),
        "waiver must declare an owner"
    );
    assert!(
        spec_waiver_active(WAIVER_REL),
        "SPEC waiver must not be expired — renew or wire cargo-rdme before expiry"
    );
}
