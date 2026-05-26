use keyhog_scanner::types::ScannerPreprocessedText;
use keyhog_scanner::{compute_line_offsets, match_line_number};

#[test]
fn last_line_offset_resolves_correctly() {
    let text = "first\nsecond\nthird";
    let pre = ScannerPreprocessedText::passthrough(text);
    let offsets = compute_line_offsets(text);
    let last_offset = text.find("third").unwrap();
    assert_eq!(match_line_number(&pre, &offsets, last_offset), 3);
}
