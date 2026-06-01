//! Top-50 chunk-boundary oracle: `google-forms-api-credentials` near-miss must NOT fire when split across chunks.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_google_forms_api_credentials_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "google-forms-api-credentials",
        "GOOGLE_FORMS=short",
    );
}
