use keyhog_scanner::context::CodeContext;
use keyhog_scanner::should_suppress_known_example_credential;

#[test]
fn b64_wrapped_example_suppressed() {
    assert!(should_suppress_known_example_credential(
        "Z2hwX0VYQU1QTEVfVE9LRU5fRlJPTV9ET0NT",
        None,
        CodeContext::Unknown,
    ));
}
