//! Top-50 detector oracle: `google-cloud-sovereign-credentials` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_google_cloud_sovereign_credentials_near_miss_must_not_fire() {
    assert_detector_silent("google-cloud-sovereign-credentials", "GOOGLE_CLOUD_SOVEREIGN=short");
}
