//! Top-50 detector oracle: `gravity-forms-rest-api-key` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_gravity_forms_rest_api_key_near_miss_must_not_fire() {
    assert_detector_silent("gravity-forms-rest-api-key", "GRAVITY_FORMS=short");
}
