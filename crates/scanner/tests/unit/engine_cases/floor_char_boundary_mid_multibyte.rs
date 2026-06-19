use keyhog_scanner::testing::floor_char_boundary;
#[test]
fn floor_char_boundary_mid_multibyte() {
    let text = "aαb";
    assert_eq!(floor_char_boundary(text, 2), 1);
}
