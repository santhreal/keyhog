//! Fail-closed weight-buffer parser (`ml_scorer/ml_weights.rs::parse_weights`),
//! reached via the `keyhog_scanner::testing` facade. Migrated from an inline
//! `#[cfg(test)]` block to satisfy the `ml_weights_no_inline_tests` gate (and
//! `ml_weights_no_unwrap_expect` — the unwrap/expect hits were test-body only).

use keyhog_scanner::testing::{
    ml_weights_embedded_bytes, ml_weights_total_f32_count,
    parse_ml_weights_for_test as parse_weights,
};

fn zeroed_buffer() -> Vec<u8> {
    vec![0u8; ml_weights_total_f32_count() * 4]
}

#[test]
fn parse_weights_accepts_correctly_sized_finite_buffer() {
    let parsed = parse_weights(&zeroed_buffer()).expect("all-zero f32 is finite");
    assert_eq!(parsed.len(), ml_weights_total_f32_count());
}

#[test]
fn parse_weights_rejects_size_mismatch() {
    let err = parse_weights(&[0u8; 4]).expect_err("short buffer must fail");
    assert!(err.contains("does not match expected"), "{err}");
}

#[test]
fn parse_weights_fails_closed_on_non_finite_value() {
    let mut buf = zeroed_buffer();
    buf[7 * 4..7 * 4 + 4].copy_from_slice(&f32::NAN.to_le_bytes());
    let err = parse_weights(&buf).expect_err("NaN weight must fail closed");
    assert!(err.contains("index 7"), "{err}");
    assert!(err.contains("non-finite"), "{err}");

    let mut inf_buf = zeroed_buffer();
    inf_buf[0..4].copy_from_slice(&f32::INFINITY.to_le_bytes());
    assert!(
        parse_weights(&inf_buf).is_err(),
        "inf weight must fail closed"
    );
}

#[test]
fn embedded_weights_bin_is_finite_and_correctly_sized() {
    let parsed = parse_weights(ml_weights_embedded_bytes())
        .expect("shipped weights.bin must pass fail-closed check");
    assert_eq!(parsed.len(), ml_weights_total_f32_count());
}
