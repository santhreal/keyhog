use keyhog_verifier::oob::OobConfig;

#[test]
fn oob_config_defaults_safe() {
    let c = OobConfig::default();
    assert_eq!(c.server, "oast.fun");
    assert!(c.default_timeout <= c.max_timeout);
    assert!(c.poll_interval < c.default_timeout);
}
