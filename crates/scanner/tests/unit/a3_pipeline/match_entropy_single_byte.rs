use keyhog_scanner::match_entropy;

#[test]
fn uniform_single_byte_has_zero_entropy() {
    assert!((match_entropy(b"a") - 0.0).abs() < f64::EPSILON);
}
