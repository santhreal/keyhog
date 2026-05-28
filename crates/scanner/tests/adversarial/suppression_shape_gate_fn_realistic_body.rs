//! KH-GAP-126 FN twin: realistic generic-password must fire through pipeline.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_fires;

#[test]
fn generic_password_realistic_body_not_suppressed_in_pipeline() {
    assert_detector_fires(
        "generic-password",
        "password=S4oxj2N-bVEi6ivQsrW3",
        "S4oxj2N-bVEi6ivQsrW3",
    );
}
