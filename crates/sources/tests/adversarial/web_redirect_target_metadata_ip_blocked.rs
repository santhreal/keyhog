//! WebSource SSRF gate must block redirect-target host `http://169.254.169.254/latest/meta-data/`.

use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "web")]
#[test]
fn web_redirect_target_metadata_ip_blocked() {
    assert!(
        TestApi.is_disallowed_web_host("http://169.254.169.254/latest/meta-data/"),
        "redirect SSRF gate must block metadata IP redirect target"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_redirect_target_metadata_ip_blocked() {}
