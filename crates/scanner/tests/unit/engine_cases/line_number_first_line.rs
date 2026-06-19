use keyhog_scanner::testing::line_number_for_offset;
#[test]
fn line_number_first_line() {
    assert_eq!(line_number_for_offset("alpha", 0), 1);
}
