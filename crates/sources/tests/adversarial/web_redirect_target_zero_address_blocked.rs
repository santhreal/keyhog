//! WebSource SSRF gate must block redirect-target host `http://0.0.0.0/hook.js`.

use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "web")]
#[test]
fn web_redirect_target_zero_address_blocked() {
    assert!(
        TestApi.is_disallowed_web_host("http://0.0.0.0/hook.js"),
        "redirect SSRF gate must block 0.0.0.0 redirect target"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_redirect_target_zero_address_blocked() {}
