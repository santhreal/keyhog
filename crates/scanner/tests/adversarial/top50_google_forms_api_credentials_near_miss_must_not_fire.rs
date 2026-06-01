//! Top-50 detector oracle: `google-forms-api-credentials` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_google_forms_api_credentials_near_miss_must_not_fire() {
    assert_detector_silent("google-forms-api-credentials", "GOOGLE_FORMS=short");
}
