//! Top-50 chunk-boundary oracle: `lastpass-dev-creds` near-miss must NOT fire when split across chunks.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_lastpass_dev_creds_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "lastpass-dev-creds",
        "microsoft_advertising client_id=YOUR_API_KEY_HERE_PLACEHOLDER_VALUE",
    );
}
