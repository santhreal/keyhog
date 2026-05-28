//! Top-50 chunk-boundary oracle: `spotify-client-credentials` near-miss must NOT fire when split across chunks.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_spotify_client_credentials_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "spotify-client-credentials",
        "SPOTIFY_CLIENT_ID=short",
    );
}
