//! KH-GAP-130: santh-ci migration SPEC waiver must document owner, reason, and expiry.

#[path = "support/mod.rs"]
mod support;

use support::spec_waiver::{repo_root, spec_waiver_active};

const WAIVER_REL: &str = "tools/ci-operability/spec_waivers/ci_yml_santh_ci_migration.toml";

#[test]
fn ci_yml_spec_waiver_has_expiry() {
    let waiver = std::fs::read_to_string(repo_root().join(WAIVER_REL)).expect("waiver TOML");
    assert!(
        waiver.contains("gap_id = \"KH-GAP-130\""),
        "waiver must name KH-GAP-130"
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
        "SPEC waiver must not be expired — renew or migrate ci.yml before expiry"
    );
}
