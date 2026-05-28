#[test]
fn entropy_new_norm_ab_pattern() {
    assert!(keyhog_scanner::entropy::normalized_entropy(b"abababab") <= 1.0);
}
