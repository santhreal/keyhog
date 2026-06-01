//! Top-50 detector oracle: `sanity-api-token` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_sanity_api_token_near_miss_must_not_fire() {
    assert_detector_silent("sanity-api-token", "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE");
}
