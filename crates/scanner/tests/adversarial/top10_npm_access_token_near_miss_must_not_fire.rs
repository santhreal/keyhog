//! Top-10 detector oracle: `npm-access-token` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top10_npm_access_token_near_miss_must_not_fire() {
    assert_detector_silent("npm-access-token", r"npm install some-package");
}
