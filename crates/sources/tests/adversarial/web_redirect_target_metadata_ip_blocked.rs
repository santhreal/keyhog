//! WebSource SSRF gate must block redirect-target host `http://169.254.169.254/latest/meta-data/`.

#[cfg(feature = "web")]
#[test]
fn web_redirect_target_metadata_ip_blocked() {
    assert!(
        keyhog_sources::testing::is_disallowed_web_host("http://169.254.169.254/latest/meta-data/"),
        "redirect SSRF gate must block metadata IP redirect target"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_redirect_target_metadata_ip_blocked() {}
