use keyhog_scanner::{
    testing::{compute_line_offsets, match_line_number},
    types::ScannerPreprocessedText,
};

#[test]
fn mid_line_byte_resolves_to_line_two() {
    let text = "line1\nline2\nline3";
    let pp = ScannerPreprocessedText::passthrough(text);
    let offsets = compute_line_offsets(text);
    let off = text.find('2').unwrap();
    assert_eq!(match_line_number(&pp, &offsets, off), 2);
}
