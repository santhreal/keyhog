//! Top-50 detector oracle: `sentry-dsn` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_sentry_dsn_near_miss_must_not_fire() {
    assert_detector_silent("sentry-dsn", "https://abc@o12345.ingest.sentry.io/67890");
}
