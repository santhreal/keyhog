use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn b64_wrapped_example_suppressed() {
    assert!(known_example_suppressed(
        "Z2hwX0VYQU1QTEVfVE9LRU5fRlJPTV9ET0NT",
        None,
        CodeContext::Unknown,
    ));
}
