//! Top-50 detector oracle: `line-api-token` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_line_api_token_near_miss_must_not_fire() {
    assert_detector_silent("line-api-token", "CHANNEL_ACCESS_TOKEN=short");
}
