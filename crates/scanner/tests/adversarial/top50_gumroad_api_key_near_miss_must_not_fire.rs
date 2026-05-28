//! Top-50 detector oracle: `gumroad-api-key` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_gumroad_api_key_near_miss_must_not_fire() {
    assert_detector_silent("gumroad-api-key", "GUMROAD=short");
}
