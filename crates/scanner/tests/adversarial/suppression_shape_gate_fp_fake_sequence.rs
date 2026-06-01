//! KH-GAP-126 FP twin: fake-sequence generic-password must not surface.

use super::oracle_support::assert_detector_silent;

#[test]
fn generic_password_fake_sequence_suppressed_in_pipeline() {
    assert_detector_silent("generic-password", "password=12345678901234567890");
}
