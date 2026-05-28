//! R5-T http adversarial: blocks IPv4-mapped loopback.

#[cfg(feature = "web")]
#[test]
fn r5t_web_blocks_ipv4_mapped_loopback() {
    assert!(keyhog_sources::testing::is_disallowed_web_host("http://[::ffff:127.0.0.1]/hook.js"));
}

#[cfg(not(feature = "web"))]
#[test]
fn r5t_web_blocks_ipv4_mapped_loopback() {}
