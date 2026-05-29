//! Top-10 detector oracle: `twilio-auth-token` true positive MUST fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_fires;

#[test]
fn top10_twilio_auth_token_true_positive_must_fire() {
    assert_detector_fires(
        "twilio-auth-token",
        "TWILIO_ACCOUNT_SID=AC00000000000000000000000000000000\nTWILIO_AUTH_TOKEN=00000000000000000000000000000000\n",
        "00000000000000000000000000000000",
    );
}
