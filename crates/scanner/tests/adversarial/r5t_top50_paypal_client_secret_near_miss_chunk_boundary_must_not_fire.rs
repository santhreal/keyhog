//! R5-T chunk-boundary near-miss: `paypal-client-secret` must NOT fire when split.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn r5t_top50_paypal_client_secret_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary(
        "paypal-client-secret",
        "EPM-DUMMY-NEAR-MISS-SECRET-000000000000",
    );
}
