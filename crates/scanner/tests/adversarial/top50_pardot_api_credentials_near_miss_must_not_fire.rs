//! Top-50 detector oracle: `pardot-api-credentials` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_pardot_api_credentials_near_miss_must_not_fire() {
    assert_detector_silent("pardot-api-credentials", "PARDOT=YOUR_API_KEY_HERE_PLACEHOLDER_VALUE");
}
