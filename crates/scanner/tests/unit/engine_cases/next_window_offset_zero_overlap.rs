use keyhog_scanner::testing::{next_window_offset, window_end_offset};
#[test]
fn next_window_offset_zero_overlap() {
    let text = "0123456789";
    let end = window_end_offset(text, 0, 5);
    assert_eq!(next_window_offset(text, end, 0), end);
}
