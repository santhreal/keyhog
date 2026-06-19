use keyhog_scanner::testing::{next_window_offset, window_end_offset};
#[test]
fn next_window_offset_at_text_end() {
    let text = "x";
    let end = window_end_offset(text, 0, 1);
    assert_eq!(end, 1);
    // Overlap larger than end clamps to 0 (start of text).
    assert_eq!(next_window_offset(text, end, 5), 0);
}
