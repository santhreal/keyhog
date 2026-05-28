//! Top-50 detector oracle: `kafka-sasl-credentials` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_kafka_sasl_credentials_near_miss_must_not_fire() {
    assert_detector_silent("kafka-sasl-credentials", "SASL_PLAINTEXT=short");
}
