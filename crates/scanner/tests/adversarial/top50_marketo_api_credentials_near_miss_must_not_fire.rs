//! Top-50 detector oracle: `marketo-api-credentials` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_marketo_api_credentials_near_miss_must_not_fire() {
    assert_detector_silent(
        "marketo-api-credentials",
        "MARKETO_CLIENT_ID=YOUR_API_KEY_HERE_PLACEHOLDER_VALUE",
    );
}
