//! R5-T http adversarial: blocks metadata.google.internal.

#[cfg(feature = "web")]
#[test]
fn r5t_web_blocks_metadata_google_internal() {
    assert!(keyhog_sources::testing::is_disallowed_web_host("http://metadata.google.internal/computeMetadata/v1/"));
}

#[cfg(not(feature = "web"))]
#[test]
fn r5t_web_blocks_metadata_google_internal() {}
