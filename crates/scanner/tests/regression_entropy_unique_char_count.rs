use keyhog_scanner::testing::{
    entropy_unique_byte_count_for_test as unique_byte_count,
    entropy_unique_char_count_for_test as unique_char_count,
};

#[test]
fn unique_char_count_ascii_matches_canonical_byte_count() {
    for (probe, expected) in [
        ("aabbc", 3),
        ("AaAaAa", 2),
        ("0123456789abcdef0123", 16),
        ("", 0),
    ] {
        assert_eq!(unique_char_count(probe), expected, "probe={probe:?}");
        assert_eq!(
            unique_char_count(probe),
            unique_byte_count(probe.as_bytes()),
            "ASCII distinct chars and bytes must agree for {probe:?}",
        );
    }
}

#[test]
fn unique_char_count_non_ascii_counts_chars_not_bytes() {
    assert_eq!(unique_char_count("café"), 4);
    assert_eq!("café".len(), 5);
    assert_eq!(unique_char_count("ééé"), 1);
}
