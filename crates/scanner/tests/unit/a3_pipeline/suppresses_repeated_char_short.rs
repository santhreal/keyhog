use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn short_repeated_digits_suppressed() {
    assert!(known_example_suppressed(
        "111111111111",
        None,
        CodeContext::Unknown,
    ));
}
