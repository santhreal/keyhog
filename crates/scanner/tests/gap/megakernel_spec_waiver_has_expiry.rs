//! KH-GAP-043 SPEC waiver must document owner, reason, and a future expiry date.

#[path = "../support/mod.rs"]
mod support;

#[test]
fn megakernel_spec_waiver_has_expiry() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/spec_waivers/megakernel_literal_set_parity.toml"
    );
    let raw = std::fs::read_to_string(path).expect("SPEC waiver TOML must exist");
    assert!(
        raw.contains("gap_id = \"KH-GAP-043\""),
        "waiver must name KH-GAP-043"
    );
    assert!(
        raw.contains("kind = \"spec\""),
        "waiver must declare kind = spec"
    );
    assert!(
        raw.contains("expires = \""),
        "waiver must declare expires = \"YYYY-MM-DD\""
    );
    assert!(raw.contains("owner = \""), "waiver must declare an owner");
    assert!(
        support::megakernel_waiver::megakernel_parity_waiver_active(),
        "SPEC waiver must not be expired — renew or wire megakernel parity before expiry"
    );
}
