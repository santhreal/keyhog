//! Top-50 detector oracle: `mailgun-api-key` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_mailgun_api_key_near_miss_must_not_fire() {
    assert_detector_silent("mailgun-api-key", "key-short");
}
