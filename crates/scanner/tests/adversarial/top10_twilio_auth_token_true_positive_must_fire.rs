//! Top-10 detector oracle: `twilio-auth-token` true positive MUST fire.

use super::oracle_support::assert_detector_fires;

#[test]
fn top10_twilio_auth_token_true_positive_must_fire() {
    assert_detector_fires(
        "twilio-auth-token",
        "TWILIO_ACCOUNT_SID=AC1234567890abcdef1234567890abcdef\nTWILIO_AUTH_TOKEN=abcdef1234567890abcdef1234567890\n",
        "abcdef1234567890abcdef1234567890",
    );
}
