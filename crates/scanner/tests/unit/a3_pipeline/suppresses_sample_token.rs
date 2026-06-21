use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn sample_word_suppresses_credential() {
    assert!(known_example_suppressed(
        "SAMPLE_API_TOKEN",
        None,
        CodeContext::Documentation,
    ));
}
