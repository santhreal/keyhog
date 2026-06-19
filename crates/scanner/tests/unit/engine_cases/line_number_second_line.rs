use keyhog_scanner::testing::line_number_for_offset;
#[test]
fn line_number_second_line() {
    let text = "line1
line2";
    assert_eq!(line_number_for_offset(text, 6), 2);
}
