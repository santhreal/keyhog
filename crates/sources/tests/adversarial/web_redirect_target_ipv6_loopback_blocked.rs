//! WebSource SSRF gate must block redirect-target host `http://[::1]/app.js`.

#[cfg(feature = "web")]
#[test]
fn web_redirect_target_ipv6_loopback_blocked() {
    assert!(
        keyhog_sources::testing::is_disallowed_web_host("http://[::1]/app.js"),
        "redirect SSRF gate must block IPv6 loopback redirect target"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_redirect_target_ipv6_loopback_blocked() {}
