//! Top-50 detector oracle: `idenfy-api-credentials` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_idenfy_api_credentials_near_miss_must_not_fire() {
    assert_detector_silent("idenfy-api-credentials", "idenfy=short");
}
