//! Top-50 chunk-boundary oracle: `google-cloud-sovereign-credentials` near-miss must NOT fire when split across chunks.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_google_cloud_sovereign_credentials_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary("google-cloud-sovereign-credentials", "GOOGLE_CLOUD_SOVEREIGN=short");
}
