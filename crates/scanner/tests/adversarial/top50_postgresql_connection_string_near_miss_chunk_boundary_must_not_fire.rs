//! Top-50 chunk-boundary oracle: `postgresql-connection-string` near-miss must NOT fire when split across chunks.

use super::oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_postgresql_connection_string_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "postgresql-connection-string",
        "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE",
    );
}
