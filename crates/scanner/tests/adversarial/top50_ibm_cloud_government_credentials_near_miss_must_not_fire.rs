//! Top-50 detector oracle: `ibm-cloud-government-credentials` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_ibm_cloud_government_credentials_near_miss_must_not_fire() {
    assert_detector_silent("ibm-cloud-government-credentials", "IBM_CLOUD_GOV=short");
}
