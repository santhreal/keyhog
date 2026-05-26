use keyhog_scanner::context::CodeContext;
use keyhog_scanner::should_suppress_known_example_credential;

#[test]
fn short_repeated_digits_suppressed() {
    assert!(should_suppress_known_example_credential(
        "111111111111",
        None,
        CodeContext::Unknown,
    ));
}
