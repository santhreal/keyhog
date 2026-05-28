//! Top-50 detector oracle: `postgresql-connection-string` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_postgresql_connection_string_near_miss_must_not_fire() {
    assert_detector_silent("postgresql-connection-string", "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE");
}
