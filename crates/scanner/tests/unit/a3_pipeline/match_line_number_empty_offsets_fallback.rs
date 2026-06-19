use keyhog_scanner::testing::match_line_number;
use keyhog_scanner::types::ScannerPreprocessedText;

#[test]
fn empty_offsets_falls_back_to_line_one() {
    let preprocessed = ScannerPreprocessedText::passthrough("solo line");
    assert_eq!(match_line_number(&preprocessed, &[], 0), 1);
}
