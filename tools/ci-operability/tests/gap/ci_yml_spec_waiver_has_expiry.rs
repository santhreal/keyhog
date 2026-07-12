//! KH-GAP-130: santh-ci migration SPEC waiver must document owner, reason, and expiry.

use super::support::spec_waiver::spec_waiver_active;
use super::support::{repo_root, CI_YML_WAIVER as WAIVER_REL};

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
