//! R5-T chunk-boundary near-miss: `firebase-api-key` must NOT fire when split.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn r5t_top50_firebase_api_key_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "firebase-api-key",
        "AIzaSyDUMMYKEYFORNEARMISS000000000000000",
    );
}
