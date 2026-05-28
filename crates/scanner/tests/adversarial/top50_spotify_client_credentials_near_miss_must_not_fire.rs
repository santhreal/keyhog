//! Top-50 detector oracle: `spotify-client-credentials` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_spotify_client_credentials_near_miss_must_not_fire() {
    assert_detector_silent("spotify-client-credentials", "SPOTIFY_CLIENT_ID=short");
}
