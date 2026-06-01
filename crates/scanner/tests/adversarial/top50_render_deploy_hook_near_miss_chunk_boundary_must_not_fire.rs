//! Top-50 chunk-boundary oracle: `render-deploy-hook` near-miss must NOT fire when split across chunks.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_render_deploy_hook_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "render-deploy-hook",
        "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE",
    );
}
