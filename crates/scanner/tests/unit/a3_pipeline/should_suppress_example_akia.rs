use keyhog_scanner::context::CodeContext;
use keyhog_scanner::should_suppress_known_example_credential;

#[test]
fn aws_example_key_suppressed_in_assignment() {
    assert!(should_suppress_known_example_credential(
        "AKIAIOSFODNN7EXAMPLE",
        None,
        CodeContext::Assignment,
    ));
}
