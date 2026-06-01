//! R5-T chunk-boundary near-miss: `docker-hub-token` must NOT fire when split.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn r5t_top50_docker_hub_token_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "docker-hub-token",
        "dckr_pat_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    );
}
