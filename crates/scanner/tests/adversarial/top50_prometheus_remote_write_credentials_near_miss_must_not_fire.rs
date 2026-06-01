//! Top-50 detector oracle: `prometheus-remote-write-credentials` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top50_prometheus_remote_write_credentials_near_miss_must_not_fire() {
    assert_detector_silent(
        "prometheus-remote-write-credentials",
        "prometheus-remote-write-credentials keyword without valid credential shape",
    );
}
