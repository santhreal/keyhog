use keyhog_scanner::testing::match_entropy;

#[test]
fn two_symbol_uniform_is_one_bit() {
    assert!((match_entropy(b"abab") - 1.0).abs() < 0.01);
}
