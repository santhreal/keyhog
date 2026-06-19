use keyhog_scanner::testing::window_end_offset;
#[test]
fn window_end_offset_invalid_start() {
    let text = "hello";
    assert_eq!(window_end_offset(text, text.len(), 10), text.len());
}
