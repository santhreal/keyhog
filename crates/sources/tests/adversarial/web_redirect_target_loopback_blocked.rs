//! WebSource SSRF gate must block redirect-target host `http://127.0.0.1/after-redirect.js`.

use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "web")]
#[test]
fn web_redirect_target_loopback_blocked() {
    assert!(
        TestApi.is_disallowed_web_host("http://127.0.0.1/after-redirect.js"),
        "redirect SSRF gate must block http://127.0.0.1/after-redirect.js"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_redirect_target_loopback_blocked() {}
