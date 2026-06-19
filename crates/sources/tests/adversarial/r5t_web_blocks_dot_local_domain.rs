//! R5-T http adversarial: blocks *.local domains.

use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "web")]
#[test]
fn r5t_web_blocks_dot_local_domain() {
    assert!(TestApi.is_disallowed_web_host("http://printer.local/config.js"));
}

#[cfg(not(feature = "web"))]
#[test]
fn r5t_web_blocks_dot_local_domain() {}
