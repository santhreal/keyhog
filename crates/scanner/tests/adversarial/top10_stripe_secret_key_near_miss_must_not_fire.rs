//! Top-10 detector oracle: `stripe-secret-key` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top10_stripe_secret_key_near_miss_must_not_fire() {
    assert_detector_silent("stripe-secret-key", r"sk_live_short");
}
