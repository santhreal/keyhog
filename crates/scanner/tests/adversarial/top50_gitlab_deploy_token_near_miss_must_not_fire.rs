//! Top-50 detector oracle: `gitlab-deploy-token` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_gitlab_deploy_token_near_miss_must_not_fire() {
    assert_detector_silent("gitlab-deploy-token", "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE");
}
