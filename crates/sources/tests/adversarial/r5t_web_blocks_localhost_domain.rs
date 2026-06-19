//! R5-T http adversarial: WebSource SSRF gate blocks localhost domain.

use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "web")]
#[test]
fn r5t_web_blocks_localhost_domain() {
    assert!(TestApi.is_disallowed_web_host("http://localhost/secret.js"));
}

#[cfg(not(feature = "web"))]
#[test]
fn r5t_web_blocks_localhost_domain() {}
