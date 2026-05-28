//! LR1-A8 replacement gate: `s3/mod.rs` empty bucket name.

#[cfg(feature = "s3")]
use keyhog_core::Source;
#[cfg(feature = "s3")]
use keyhog_sources::S3Source;

#[cfg(feature = "s3")]
#[test]
fn s3_source_empty_bucket_still_named_s3() {
    let source = S3Source::new("");
    assert_eq!(source.name(), "s3");
}

#[cfg(not(feature = "s3"))]
#[test]
fn s3_gate_skipped_without_feature() {
    // s3 feature disabled in default test build - gate lives behind feature flag.
}
