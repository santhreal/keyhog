//! Top-50 detector oracle: `google-artifact-registry-key` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_google_artifact_registry_key_near_miss_must_not_fire() {
    assert_detector_silent("google-artifact-registry-key", "_json_key=short");
}
