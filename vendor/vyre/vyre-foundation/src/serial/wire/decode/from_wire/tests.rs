use super::reserve_decoded_vec_capacity;

#[test]
fn wire_decode_reservation_reports_capacity_overflow() {
    let mut bytes = Vec::<u8>::new();
    let error = reserve_decoded_vec_capacity(&mut bytes, usize::MAX, "test wire bytes")
        .expect_err("Fix: impossible wire reserve must fail before allocation.");

    assert!(
        error.contains("failed to reserve test wire bytes"),
        "Fix: wire decode reserve errors must name the field that failed: {error}"
    );
}

#[test]
fn wire_decode_reservation_reuses_existing_capacity() {
    let mut bytes = Vec::<u8>::with_capacity(16);
    let original_capacity = bytes.capacity();

    reserve_decoded_vec_capacity(&mut bytes, 8, "test wire bytes")
        .expect("Fix: lower target capacity should reuse existing decode storage.");

    assert_eq!(bytes.capacity(), original_capacity);
}
