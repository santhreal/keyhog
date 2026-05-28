#[test]
fn entropy_new_norm_single_byte_zero() {
    assert_eq!(keyhog_scanner::entropy::normalized_entropy(b"aaaa"), 0.0);
}
