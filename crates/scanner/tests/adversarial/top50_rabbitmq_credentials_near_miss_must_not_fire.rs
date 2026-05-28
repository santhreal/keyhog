//! Top-50 detector oracle: `rabbitmq-credentials` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_rabbitmq_credentials_near_miss_must_not_fire() {
    assert_detector_silent("rabbitmq-credentials", "amqps://YOUR_API_KEY_HERE_PLACEHOLDER_VALUE:YOUR_API_KEY_HERE_PLACEHOLDER_VALUE@rabbitmq.example.com:5671/vhost");
}
