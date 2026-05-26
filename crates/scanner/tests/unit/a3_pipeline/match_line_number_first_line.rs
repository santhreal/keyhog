use keyhog_scanner::types::ScannerPreprocessedText;
use keyhog_scanner::{compute_line_offsets, match_line_number};

#[test]
fn offset_zero_maps_to_line_one() {
    let text = "first\nsecond";
    let pre = ScannerPreprocessedText::passthrough(text);
    let offsets = compute_line_offsets(text);
    assert_eq!(match_line_number(&pre, &offsets, 0), 1);
}
