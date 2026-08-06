use keyhog_scanner::testing::code_lines_from_compact_index_for_test;

#[test]
fn compact_line_index_matches_str_lines() {
    for text in [
        "",
        "one",
        "one\n",
        "one\ntwo",
        "one\ntwo\n",
        "\n",
        "\n\n",
        "one\r\ntwo\r\n",
        "one\r\ntwo\r",
        "one\r",
    ] {
        let derived =
            code_lines_from_compact_index_for_test(text).expect("fixture fits compact index");
        let expected: Vec<&str> = text.lines().collect();
        assert_eq!(derived, expected, "line split mismatch for {text:?}");
    }
}
