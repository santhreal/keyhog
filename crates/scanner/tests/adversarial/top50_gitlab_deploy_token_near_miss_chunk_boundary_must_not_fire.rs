//! Top-50 chunk-boundary oracle: `gitlab-deploy-token` near-miss must NOT fire when split across chunks.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_gitlab_deploy_token_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "gitlab-deploy-token",
        "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE",
    );
}
