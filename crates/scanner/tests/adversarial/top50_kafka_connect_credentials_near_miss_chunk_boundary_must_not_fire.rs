//! Top-50 chunk-boundary oracle: `kafka-connect-credentials` near-miss must NOT fire when split across chunks.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_kafka_connect_credentials_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "kafka-connect-credentials",
        "connect.password=short",
    );
}
