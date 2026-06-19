//! R5-T http adversarial: blocks metadata.google.internal.

use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "web")]
#[test]
fn r5t_web_blocks_metadata_google_internal() {
    assert!(TestApi.is_disallowed_web_host("http://metadata.google.internal/computeMetadata/v1/"));
}

#[cfg(not(feature = "web"))]
#[test]
fn r5t_web_blocks_metadata_google_internal() {}
