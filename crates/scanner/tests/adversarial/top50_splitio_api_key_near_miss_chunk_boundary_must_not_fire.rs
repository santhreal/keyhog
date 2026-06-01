//! Top-50 chunk-boundary oracle: `splitio-api-key` near-miss must NOT fire when split across chunks.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_splitio_api_key_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "splitio-api-key",
        "split_io_api_key=YOUR_API_KEY_HERE_PLACEHOLDER_VALUE",
    );
}
