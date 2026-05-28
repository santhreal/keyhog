//! Top-50 chunk-boundary oracle: `airtable-api-key` near-miss must NOT fire when split across chunks.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_airtable_api_key_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary("airtable-api-key", "pat9X3kQp7VbT2hYR.short");
}
