//! R5-T chunk-boundary near-miss: `vercel-api-token` must NOT fire when split.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn r5t_top50_vercel_api_token_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "vercel-api-token",
        "vercel_dummy_near_miss_token_000000000000",
    );
}
