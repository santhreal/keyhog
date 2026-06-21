use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn your_api_key_instructional_suppressed() {
    assert!(known_example_suppressed(
        "YOUR_API_KEY_HERE",
        None,
        CodeContext::Documentation,
    ));
}
