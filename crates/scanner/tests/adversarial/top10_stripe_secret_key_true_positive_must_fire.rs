//! Top-10 detector oracle: `stripe-secret-key` true positive MUST fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_fires;

#[test]
fn top10_stripe_secret_key_true_positive_must_fire() {
    assert_detector_fires(
        "stripe-secret-key",
        r"sk_live_000000000000000000000000000000000000",
        "sk_live_000000000000000000000000000000000000",
    );
}
