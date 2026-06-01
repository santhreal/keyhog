//! Top-50 detector oracle: `invision-api-key` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_invision_api_key_near_miss_must_not_fire() {
    assert_detector_silent("invision-api-key", "IPS4_API_KEY=short");
}
