//! Top-50 chunk-boundary oracle: `datadog-api-key` near-miss must NOT fire when split across chunks.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_datadog_api_key_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary("datadog-api-key", "DD_API_KEY=short");
}
