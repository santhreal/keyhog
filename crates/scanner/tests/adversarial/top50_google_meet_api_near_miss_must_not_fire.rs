//! Top-50 detector oracle: `google-meet-api` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_google_meet_api_near_miss_must_not_fire() {
    assert_detector_silent("google-meet-api", "GOOGLE_MEET=short");
}
