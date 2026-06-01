//! Top-50 chunk-boundary oracle: `google-artifact-registry-key` near-miss must NOT fire when split across chunks.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_google_artifact_registry_key_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary("google-artifact-registry-key", "_json_key=short");
}
