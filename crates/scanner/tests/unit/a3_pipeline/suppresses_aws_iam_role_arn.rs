use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn iam_role_arn_suppressed() {
    assert!(should_suppress_known_example_credential(
        "arn:aws:iam::123456789012:role/ReadOnly",
        None,
        CodeContext::Unknown,
    ));
}
