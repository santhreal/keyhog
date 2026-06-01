//! Top-50 detector oracle: `intercom-access-token` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_intercom_access_token_near_miss_must_not_fire() {
    assert_detector_silent("intercom-access-token", "dG9rshort");
}
