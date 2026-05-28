//! Top-10 detector oracle: `twilio-auth-token` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top10_twilio_auth_token_near_miss_must_not_fire() {
    assert_detector_silent(
        "twilio-auth-token",
        r"TWILIO_AUTH_TOKEN=4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f",
    );
}
