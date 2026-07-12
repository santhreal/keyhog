//! KH-GAP-111: cargo-rdme README SPEC waiver must document owner, reason, and expiry.

use super::support::spec_waiver::spec_waiver_active;
use super::support::{repo_root, CARGO_RDME_WAIVER as WAIVER_REL};

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
