//! R5-T http adversarial: blocks RFC1918 10.0.0.0/8.

#[cfg(feature = "web")]
#[test]
fn r5t_web_blocks_private_10_network() {
    assert!(keyhog_sources::testing::is_disallowed_web_host("http://10.255.255.254/internal.js"));
}

#[cfg(not(feature = "web"))]
#[test]
fn r5t_web_blocks_private_10_network() {}
