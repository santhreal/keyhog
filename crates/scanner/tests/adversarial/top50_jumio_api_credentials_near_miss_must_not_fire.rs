//! Top-50 detector oracle: `jumio-api-credentials` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_jumio_api_credentials_near_miss_must_not_fire() {
    assert_detector_silent("jumio-api-credentials", "jumio=short");
}
