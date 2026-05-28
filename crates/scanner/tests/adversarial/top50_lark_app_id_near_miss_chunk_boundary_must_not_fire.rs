//! Top-50 chunk-boundary oracle: `lark-app-id` near-miss must NOT fire when split across chunks.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_lark_app_id_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary("lark-app-id", "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE");
}
