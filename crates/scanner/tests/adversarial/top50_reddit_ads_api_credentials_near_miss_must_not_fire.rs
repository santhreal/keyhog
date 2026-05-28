//! Top-50 detector oracle: `reddit-ads-api-credentials` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_reddit_ads_api_credentials_near_miss_must_not_fire() {
    assert_detector_silent("reddit-ads-api-credentials", "reddit_ads_client_id=YOUR_API_KEY_HERE_PLACEHOLDER_VALUE");
}
