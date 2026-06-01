//! Top-50 detector oracle: `mongodb-connection-string` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_mongodb_connection_string_near_miss_must_not_fire() {
    assert_detector_silent("mongodb-connection-string", "mongodb://localhost");
}
