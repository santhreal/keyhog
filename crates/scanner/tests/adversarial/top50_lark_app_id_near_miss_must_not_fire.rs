//! Top-50 detector oracle: `lark-app-id` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_lark_app_id_near_miss_must_not_fire() {
    assert_detector_silent("lark-app-id", "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE");
}
