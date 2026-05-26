//! LR1-A8 replacement gate: `oob/mod.rs` default server hostname.

use keyhog_verifier::oob::OobConfig;

#[test]
fn oob_config_default_server_is_fqdn() {
    let cfg = OobConfig::default();
    assert!(
        cfg.server.contains('.'),
        "default OOB server must be a fully qualified domain, got {:?}",
        cfg.server
    );
}
