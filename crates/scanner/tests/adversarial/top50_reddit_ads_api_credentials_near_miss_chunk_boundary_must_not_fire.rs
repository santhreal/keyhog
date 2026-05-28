//! Top-50 chunk-boundary oracle: `reddit-ads-api-credentials` near-miss must NOT fire when split across chunks.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_reddit_ads_api_credentials_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=YOUR_API_KEY_HERE_PLACEHOLDER_VALUE",
    );
}
