//! Top-50 chunk-boundary oracle: `intercom-access-token` near-miss must NOT fire when split across chunks.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_intercom_access_token_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary("intercom-access-token", "dG9rshort");
}
