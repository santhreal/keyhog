//! Top-10 detector oracle: `twilio-auth-token` true positive MUST fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_fires;

#[test]
fn top10_twilio_auth_token_true_positive_must_fire() {
    assert_detector_fires(
        "twilio-auth-token",
        "TWILIO_ACCOUNT_SID=AC7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\nTWILIO_AUTH_TOKEN=4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f\n",
        "4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f",
    );
}
