use keyhog_scanner::testing::window_end_offset;
#[test]
fn window_end_offset_ascii_stays_in_bounds() {
    let text = "hello world";
    let end = window_end_offset(text, 0, 5);
    assert_eq!(end, 5);
    assert!(text.is_char_boundary(end));
}
