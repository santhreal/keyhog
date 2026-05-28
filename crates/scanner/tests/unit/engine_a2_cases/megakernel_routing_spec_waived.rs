//! KH-GAP-043 SPEC waiver: MegakernelScanner dispatch is not wired
//! in `engine/` yet. `KEYHOG_USE_MEGAKERNEL` must remain a no-op until vyre exposes
//! a stable megakernel hook; `gap/megakernel_literal_set_parity.rs` is waived via
//! `spec_waivers/megakernel_literal_set_parity.toml` until expiry.

#[path = "../../support/mod.rs"]
mod support;

#[test]
fn megakernel_env_not_wired_in_engine_yet() {
    assert!(
        support::megakernel_waiver::megakernel_env_unwired_in_engine(),
        "partial megakernel wiring forbidden until parity contract is met"
    );
    assert!(
        support::megakernel_waiver::megakernel_parity_waiver_active(),
        "SPEC waiver must remain active while megakernel is unwired"
    );
}
