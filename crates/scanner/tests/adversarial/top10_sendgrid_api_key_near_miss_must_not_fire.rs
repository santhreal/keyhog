//! Top-10 detector oracle: `sendgrid-api-key` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top10_sendgrid_api_key_near_miss_must_not_fire() {
    assert_detector_silent("sendgrid-api-key", r"SG.short.short");
}
