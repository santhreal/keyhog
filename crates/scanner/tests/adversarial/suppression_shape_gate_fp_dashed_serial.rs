//! KH-GAP-126 FP twin: dashed-serial shape must not surface as generic-password.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn generic_password_dashed_serial_shape_suppressed_in_pipeline() {
    assert_detector_silent(
        "generic-password",
        "password=ABCDE-FGHIJ-KLMNO-PQRST-UVWXY",
    );
}
