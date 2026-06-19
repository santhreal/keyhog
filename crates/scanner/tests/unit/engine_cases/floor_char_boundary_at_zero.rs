use keyhog_scanner::testing::floor_char_boundary;
#[test]
fn floor_char_boundary_at_zero() {
    assert_eq!(floor_char_boundary("hello", 0), 0);
}
