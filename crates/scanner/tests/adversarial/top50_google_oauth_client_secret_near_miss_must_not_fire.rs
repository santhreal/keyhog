//! Top-50 detector oracle: `google-oauth-client-secret` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_google_oauth_client_secret_near_miss_must_not_fire() {
    assert_detector_silent("google-oauth-client-secret", "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE");
}
