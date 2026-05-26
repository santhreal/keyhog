use keyhog_scanner::match_entropy;

#[test]
fn uniform_bytes_have_zero_entropy() {
    assert_eq!(match_entropy(b"xxxxxxxx"), 0.0);
}
