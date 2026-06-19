use keyhog_scanner::testing::line_window_offsets;
use keyhog_scanner::types::ScannerPreprocessedText;

#[test]
fn line_window_offsets_returns_inclusive_range() {
    let text = "one\ntwo\nthree";
    let preprocessed = ScannerPreprocessedText::passthrough(text);
    let (start, end) = line_window_offsets(&preprocessed, 2, 2).expect("window for line 2");
    assert!(start <= end);
    assert_eq!(start, preprocessed.mappings[1].start_offset);
    assert_eq!(end, preprocessed.mappings[1].end_offset);
}
