//! Top-50 detector oracle: `cloudflare-api-token` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_cloudflare_api_token_near_miss_must_not_fire() {
    assert_detector_silent("cloudflare-api-token", "CF_API_TOKEN=short");
}
