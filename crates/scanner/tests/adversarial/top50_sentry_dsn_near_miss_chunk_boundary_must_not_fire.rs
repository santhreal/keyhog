//! Top-50 chunk-boundary oracle: `sentry-dsn` near-miss must NOT fire when split across chunks.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_sentry_dsn_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "sentry-dsn",
        "https://abc@o12345.ingest.sentry.io/67890",
    );
}
