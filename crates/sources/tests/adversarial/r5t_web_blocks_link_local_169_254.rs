//! R5-T http adversarial: blocks link-local 169.254.0.0/16.

use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "web")]
#[test]
fn r5t_web_blocks_link_local_169_254() {
    assert!(TestApi.is_disallowed_web_host("http://169.254.99.88/metadata"));
}

#[cfg(not(feature = "web"))]
#[test]
fn r5t_web_blocks_link_local_169_254() {}
