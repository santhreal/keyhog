//! Top-50 chunk-boundary oracle: `heroku-api-key` near-miss must NOT fire when split across chunks.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_heroku_api_key_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "heroku-api-key",
        "9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d",
    );
}
