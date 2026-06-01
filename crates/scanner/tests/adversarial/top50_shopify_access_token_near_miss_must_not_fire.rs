//! Top-50 detector oracle: `shopify-access-token` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_shopify_access_token_near_miss_must_not_fire() {
    assert_detector_silent("shopify-access-token", "shpca_short");
}
