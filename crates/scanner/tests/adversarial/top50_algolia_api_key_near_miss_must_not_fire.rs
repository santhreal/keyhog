//! Top-50 detector oracle: `algolia-api-key` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_algolia_api_key_near_miss_must_not_fire() {
    assert_detector_silent("algolia-api-key", "ALGOLIA_API_KEY=short");
}
