//! Top-50 chunk-boundary oracle: `cloudflare-api-token` near-miss must NOT fire when split across chunks.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_cloudflare_api_token_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary("cloudflare-api-token", "CF_API_TOKEN=short");
}
