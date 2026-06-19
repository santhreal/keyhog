use keyhog_scanner::testing::{next_window_offset, window_end_offset};
#[test]
fn next_window_offset_applies_overlap() {
    let text = "abcdefghijklmnopqrstuvwxyz";
    let end = window_end_offset(text, 0, 10);
    let next = next_window_offset(text, end, 3);
    assert!(next < end);
    assert!(text.is_char_boundary(next));
}
