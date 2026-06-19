use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn your_api_key_instructional_suppressed() {
    assert!(should_suppress_known_example_credential(
        "YOUR_API_KEY_HERE",
        None,
        CodeContext::Documentation,
    ));
}
