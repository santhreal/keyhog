//! WebSource SSRF gate must block redirect-target link-local IP hosts.

#[cfg(feature = "web")]
#[test]
fn web_redirect_target_decimal_localhost_blocked() {
    assert!(
        keyhog_sources::testing::is_disallowed_web_host("http://169.254.1.1/redirect.js"),
        "redirect SSRF gate must block link-local redirect target"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_redirect_target_decimal_localhost_blocked() {}
