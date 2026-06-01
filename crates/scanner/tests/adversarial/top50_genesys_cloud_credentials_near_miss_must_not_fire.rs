//! Top-50 detector oracle: `genesys-cloud-credentials` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_genesys_cloud_credentials_near_miss_must_not_fire() {
    assert_detector_silent("genesys-cloud-credentials", "GENESYS=short");
}
