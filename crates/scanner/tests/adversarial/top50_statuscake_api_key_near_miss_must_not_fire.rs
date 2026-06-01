//! Top-50 detector oracle: `statuscake-api-key` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_statuscake_api_key_near_miss_must_not_fire() {
    assert_detector_silent(
        "statuscake-api-key",
        "statuscake_api_key=YOUR_API_KEY_HERE_PLACEHOLDER_VALUE",
    );
}
