//! Top-50 detector oracle: `hubspot-private-app-token` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_hubspot_private_app_token_near_miss_must_not_fire() {
    assert_detector_silent("hubspot-private-app-token", "pat-=short");
}
