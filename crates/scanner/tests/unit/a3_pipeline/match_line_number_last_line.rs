use keyhog_scanner::testing::{compute_line_offsets, match_line_number, ScannerPreprocessedText};

#[test]
fn last_line_offset_resolves_correctly() {
    let text = "first\nsecond\nthird";
    let pre = ScannerPreprocessedText::passthrough(text);
    let offsets = compute_line_offsets(text);
    let last_offset = text.find("third").unwrap();
    assert_eq!(match_line_number(&pre, &offsets, last_offset), 3);
}
