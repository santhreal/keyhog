//! Top-50 detector oracle: `render-deploy-hook` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_render_deploy_hook_near_miss_must_not_fire() {
    assert_detector_silent("render-deploy-hook", "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE");
}
