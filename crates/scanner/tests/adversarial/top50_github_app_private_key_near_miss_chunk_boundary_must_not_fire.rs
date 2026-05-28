//! Top-50 chunk-boundary oracle: `github-app-private-key` near-miss must NOT fire when split across chunks.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_github_app_private_key_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "github-app-private-key",
        "-----BEGIN RSA PRIVATE KEY-----=short",
    );
}
