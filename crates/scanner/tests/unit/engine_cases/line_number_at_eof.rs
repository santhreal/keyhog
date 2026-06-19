use keyhog_scanner::testing::line_number_for_offset;
#[test]
fn line_number_at_eof() {
    let text = "a
b
c";
    assert_eq!(line_number_for_offset(text, text.len()), 3);
}
