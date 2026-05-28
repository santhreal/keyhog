//! Top-50 detector oracle: `kafka-connect-credentials` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_kafka_connect_credentials_near_miss_must_not_fire() {
    assert_detector_silent("kafka-connect-credentials", "connect.password=short");
}
