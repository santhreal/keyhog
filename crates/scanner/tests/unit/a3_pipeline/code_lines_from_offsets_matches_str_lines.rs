use keyhog_scanner::testing::{code_lines_from_offsets_for_test, compute_line_offsets};

#[test]
fn code_lines_from_offsets_matches_str_lines() {
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
        let offsets = compute_line_offsets(text);
        let derived = code_lines_from_offsets_for_test(text, &offsets);
        let expected: Vec<&str> = text.lines().collect();
        assert_eq!(derived, expected, "line split mismatch for {text:?}");
    }
}
