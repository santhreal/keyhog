use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn sample_word_suppresses_credential() {
    assert!(should_suppress_known_example_credential(
        "SAMPLE_API_TOKEN",
        None,
        CodeContext::Documentation,
    ));
}
