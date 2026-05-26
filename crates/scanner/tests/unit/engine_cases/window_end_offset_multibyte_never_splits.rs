use keyhog_scanner::engine::window_end_offset;
#[test]
fn window_end_offset_multibyte_never_splits() {
    let text = "αβγδ";
    let end = window_end_offset(text, 0, 3);
    assert!(text.is_char_boundary(end));
    assert!(end >= 3);
}
