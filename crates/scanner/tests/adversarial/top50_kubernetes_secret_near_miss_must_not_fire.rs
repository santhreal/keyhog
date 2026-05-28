//! Top-50 detector oracle: `kubernetes-secret` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_kubernetes_secret_near_miss_must_not_fire() {
    assert_detector_silent("kubernetes-secret", "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE");
}
