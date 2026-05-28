//! Top-50 detector oracle: `lastpass-dev-creds` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_lastpass_dev_creds_near_miss_must_not_fire() {
    assert_detector_silent(
        "lastpass-dev-creds",
        "microsoft_advertising client_id=YOUR_API_KEY_HERE_PLACEHOLDER_VALUE",
    );
}
