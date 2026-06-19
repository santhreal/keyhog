use keyhog_scanner::testing::floor_char_boundary;
#[test]
fn floor_char_boundary_past_end() {
    let text = "hi";
    assert_eq!(floor_char_boundary(text, 99), text.len());
}
