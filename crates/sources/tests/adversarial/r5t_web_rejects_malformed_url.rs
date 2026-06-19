//! R5-T http adversarial: malformed URL rejected.

use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "web")]
#[test]
fn r5t_web_rejects_malformed_url() {
    assert!(TestApi.is_disallowed_web_host("http://%zz:bad"));
}

#[cfg(not(feature = "web"))]
#[test]
fn r5t_web_rejects_malformed_url() {}
