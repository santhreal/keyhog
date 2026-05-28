//! Top-50 detector oracle: `splitio-api-key` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_splitio_api_key_near_miss_must_not_fire() {
    assert_detector_silent("splitio-api-key", "split_io_api_key=YOUR_API_KEY_HERE_PLACEHOLDER_VALUE");
}
