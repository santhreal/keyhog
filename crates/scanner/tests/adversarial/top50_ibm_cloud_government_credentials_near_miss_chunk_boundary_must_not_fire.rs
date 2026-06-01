//! Top-50 chunk-boundary oracle: `ibm-cloud-government-credentials` near-miss must NOT fire when split across chunks.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_ibm_cloud_government_credentials_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "ibm-cloud-government-credentials",
        "IBM_CLOUD_GOV=short",
    );
}
