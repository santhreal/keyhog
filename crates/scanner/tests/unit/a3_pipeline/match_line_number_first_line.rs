use keyhog_scanner::testing::{compute_line_offsets, match_line_number};
use keyhog_scanner::types::ScannerPreprocessedText;

#[test]
fn offset_zero_maps_to_line_one() {
    let text = "first\nsecond";
    let pre = ScannerPreprocessedText::passthrough(text);
    let offsets = compute_line_offsets(text);
    assert_eq!(match_line_number(&pre, &offsets, 0), 1);
}
