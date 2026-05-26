use keyhog_scanner::engine::window_end_offset;
#[test]
fn window_end_offset_at_eof() {
    let text = "abc";
    assert_eq!(window_end_offset(text, 0, 100), text.len());
}
