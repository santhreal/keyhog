//! Top-50 detector oracle: `github-app-private-key` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_github_app_private_key_near_miss_must_not_fire() {
    assert_detector_silent("github-app-private-key", "-----BEGIN RSA PRIVATE KEY-----=short");
}
