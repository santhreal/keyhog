use keyhog_core::ascii_ci::{is_ascii_alphanumeric_bytes, is_ascii_alphanumeric_str};

#[test]
fn ascii_alphanumeric_helpers_share_ascii_only_boundaries() {
    for (value, expected) in [
        ("", true),
        ("AbC012", true),
        ("with-dash", false),
        ("with space", false),
        ("café", false),
        ("１２３", false),
    ] {
        assert_eq!(is_ascii_alphanumeric_str(value), expected, "{value:?}");
        assert_eq!(is_ascii_alphanumeric_bytes(value.as_bytes()), expected);
    }
}
