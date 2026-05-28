//! R5-T http adversarial: WebSource SSRF gate blocks localhost domain.

#[cfg(feature = "web")]
#[test]
fn r5t_web_blocks_localhost_domain() {
    assert!(keyhog_sources::testing::is_disallowed_web_host("http://localhost/secret.js"));
}

#[cfg(not(feature = "web"))]
#[test]
fn r5t_web_blocks_localhost_domain() {}
