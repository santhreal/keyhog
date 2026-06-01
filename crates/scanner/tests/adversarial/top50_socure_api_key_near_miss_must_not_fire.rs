//! Top-50 detector oracle: `socure-api-key` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_socure_api_key_near_miss_must_not_fire() {
    assert_detector_silent(
        "socure-api-key",
        "socure api key=YOUR_API_KEY_HERE_PLACEHOLDER_VALUE",
    );
}
