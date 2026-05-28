//! WebSource SSRF gate must block redirect-target host `http://vault.internal/secret.js`.

#[cfg(feature = "web")]
#[test]
fn web_redirect_target_internal_suffix_blocked() {
    assert!(
        keyhog_sources::testing::is_disallowed_web_host("http://vault.internal/secret.js"),
        "redirect SSRF gate must block .internal redirect target"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_redirect_target_internal_suffix_blocked() {}
