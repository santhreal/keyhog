//! Top-50 chunk-boundary oracle: `rabbitmq-credentials` near-miss must NOT fire when split across chunks.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_rabbitmq_credentials_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary("rabbitmq-credentials", "amqps://YOUR_API_KEY_HERE_PLACEHOLDER_VALUE:YOUR_API_KEY_HERE_PLACEHOLDER_VALUE@rabbitmq.example.com:5671/vhost");
}
