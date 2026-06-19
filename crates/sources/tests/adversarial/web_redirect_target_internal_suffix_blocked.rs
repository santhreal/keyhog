//! WebSource SSRF gate must block redirect-target host `http://vault.internal/secret.js`.

use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "web")]
#[test]
fn web_redirect_target_internal_suffix_blocked() {
    assert!(
        TestApi.is_disallowed_web_host("http://vault.internal/secret.js"),
        "redirect SSRF gate must block .internal redirect target"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_redirect_target_internal_suffix_blocked() {}
