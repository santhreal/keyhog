use keyhog_scanner::match_entropy;

#[test]
fn mixed_alphabet_has_positive_entropy() {
    assert!(match_entropy(b"abc123XYZ") > 2.0);
}
