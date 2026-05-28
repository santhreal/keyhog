#[test]
fn entropy_new_shannon_empty_zero() {
    assert_eq!(keyhog_scanner::entropy::shannon_entropy(b""), 0.0);
}
