//! Top-50 detector oracle: `google-cloud-iot-credentials` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_google_cloud_iot_credentials_near_miss_must_not_fire() {
    assert_detector_silent("google-cloud-iot-credentials", "GOOGLE_CLOUD_IOT=short");
}
