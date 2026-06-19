use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn multiword_prose_suppressed() {
    assert!(should_suppress_known_example_credential(
        "Session opened with handle abcdef0123456789 see documentation",
        None,
        CodeContext::Unknown,
    ));
}
